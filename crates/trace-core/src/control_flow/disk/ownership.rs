//! The existing ActivationBuilder transition order, without its retained tree.
//! Disk construction must drain closed siblings to a fallible sink; keeping the
//! tree here would make memory proportional to calls rather than active depth.
use crate::error::{Result, TraceError};
use crate::query::activation::{InsnFact, UnresolvedReason};

#[derive(Clone, Debug)]
pub struct Boundary {
    pub id: u32,
    pub parent: u32,
    pub call: InsnFact,
    pub entry: Option<InsnFact>,
    pub exit: Option<InsnFact>,
    pub resume: Option<InsnFact>,
    pub expected_resume: u64,
    pub unresolved: Option<UnresolvedReason>,
}
#[derive(Clone, Debug)]
pub enum OwnershipEvent {
    Entry(Boundary),
    Closed(Boundary),
    Bypassed { parent: u32, call: InsnFact, resume: InsnFact },
}
pub trait OwnershipSink {
    fn event(&mut self, event: OwnershipEvent) -> Result<()>;
}
struct Candidate { call: InsnFact, expected: u64, parent: u32 }
struct Frame { boundary: Boundary, previous: Option<InsnFact> }
/// Bounded single-thread resolver. Root is implicit ID 0, never closed.
/// IDs are allocated at activation/unresolved creation, not at call: bypassed
/// candidates do not consume an ID, exactly as in ActivationBuilder.
pub struct OwnershipResolver {
    stack: Vec<Frame>,
    pending: Option<Candidate>,
    last: Option<InsnFact>,
    next_id: u32,
    max_depth: usize,
}
fn capacity(message: &str) -> TraceError { TraceError::InvalidArgument(message.into()) }
impl OwnershipResolver {
    pub fn new(max_depth: usize) -> Result<Self> {
        if max_depth == 0 { return Err(capacity("CFG active depth budget is zero")); }
        Ok(Self { stack: Vec::new(), pending: None, last: None, next_id: 1, max_depth })
    }
    pub fn current_id(&self) -> u32 { self.stack.last().map_or(0, |f| f.boundary.id) }
    fn boundary(&mut self, c: Candidate, entry: Option<InsnFact>) -> Result<Boundary> {
        if self.next_id == u32::MAX { return Err(capacity("CFG activation ID capacity exceeded")); }
        let id = self.next_id;
        self.next_id = id.checked_add(1).ok_or_else(|| capacity("CFG activation ID overflow"))?;
        Ok(Boundary { id, parent: c.parent, call: c.call, entry, exit: entry,
            resume: None, expected_resume: c.expected, unresolved: None })
    }
    pub fn on_insn(&mut self, fact: InsnFact, sink: &mut impl OwnershipSink) -> Result<u32> {
        // Candidate consumes the instruction before any parent resume check.
        // In particular recursive calls sharing a callsite must not pop parent.
        if let Some(c) = self.pending.take() {
            if fact.pc == c.expected {
                sink.event(OwnershipEvent::Bypassed { parent: c.parent, call: c.call, resume: fact })?;
            } else {
                if self.stack.len() >= self.max_depth { return Err(capacity("CFG active depth capacity exceeded")); }
                let boundary = self.boundary(c, Some(fact))?;
                sink.event(OwnershipEvent::Entry(boundary.clone()))?;
                self.stack.push(Frame { boundary, previous: self.last });
            }
        } else if self.stack.last().is_some_and(|f| f.boundary.expected_resume == fact.pc) {
            let mut f = self.stack.pop().unwrap();
            f.boundary.exit = self.last;
            f.boundary.resume = Some(fact);
            sink.event(OwnershipEvent::Closed(f.boundary))?;
        }
        self.last = Some(fact);
        Ok(self.current_id())
    }
    pub fn on_call(&mut self, fact: InsnFact, sink: &mut impl OwnershipSink) -> Result<()> {
        let expected = fact.pc.checked_add(4).ok_or_else(|| capacity("CFG expected resume PC overflow"))?;
        if let Some(c) = self.pending.take() {
            let mut b = self.boundary(c, None)?;
            b.unresolved = Some(UnresolvedReason::DisplacedByAnotherCall);
            sink.event(OwnershipEvent::Closed(b))?;
        }
        self.pending = Some(Candidate { call: fact, expected, parent: self.current_id() });
        Ok(())
    }
    pub fn finish(mut self, sink: &mut impl OwnershipSink) -> Result<u32> {
        if let Some(c) = self.pending.take() {
            let mut b = self.boundary(c, None)?;
            b.unresolved = Some(UnresolvedReason::NoNextInsn);
            sink.event(OwnershipEvent::Closed(b))?;
        }
        // Same truncation unwind as ActivationBuilder::finish: an outer exit
        // uses its own pre-child instruction, never the innermost child's PC.
        while let Some(mut f) = self.stack.pop() {
            f.boundary.exit = self.last;
            f.boundary.unresolved = Some(UnresolvedReason::TraceEndStillActive);
            self.last = f.previous;
            sink.event(OwnershipEvent::Closed(f.boundary))?;
        }
        Ok(self.next_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::activation::ActivationBuilder;
    #[derive(Default)] struct Sink { entries: Vec<Boundary>, closed: Vec<Boundary>, bypassed: Vec<(u32, InsnFact, InsnFact)> }
    impl OwnershipSink for Sink {
        fn event(&mut self, e: OwnershipEvent) -> Result<()> {
            match e { OwnershipEvent::Entry(b) => self.entries.push(b), OwnershipEvent::Closed(b) => self.closed.push(b),
                OwnershipEvent::Bypassed { parent, call, resume } => self.bypassed.push((parent, call, resume)) }
            Ok(())
        }
    }
    fn compare(facts: &[(u32, u64, bool)], total: u32) {
        let mut old = ActivationBuilder::new();
        let mut new = OwnershipResolver::new(8).unwrap();
        let mut sink = Sink::default();
        for &(seq, pc, call) in facts {
            let f = InsnFact::new(seq, pc);
            assert_eq!(old.on_insn(f), new.on_insn(f, &mut sink).unwrap());
            if call { old.on_call(seq, pc); new.on_call(f, &mut sink).unwrap(); }
        }
        let tree = old.finish(total);
        assert_eq!(new.finish(&mut sink).unwrap() as usize, tree.activations.len());
        sink.closed.sort_by_key(|b| b.id);
        assert_eq!(sink.closed.len() + 1, tree.activations.len());
        for (b, a) in sink.closed.iter().zip(&tree.activations[1..]) {
            assert_eq!((b.id, b.parent, b.call.seq, b.call.pc, b.expected_resume, b.unresolved),
                (a.id, a.parent_id.unwrap(), a.call_seq, a.call_pc, a.expected_resume, a.unresolved_reason));
            assert_eq!(b.entry.map(|f| (f.seq, f.pc)).unwrap_or((0,0)), (a.entry_seq, a.entry_pc));
            assert_eq!(b.exit.map(|f| (f.seq, f.pc)).unwrap_or((0,0)), (a.exit_seq, a.exit_pc));
            assert_eq!(b.resume.map_or(0, |f| f.seq), a.resume_seq);
        }
        assert_eq!(sink.bypassed.len(), tree.bypassed_calls.len());
        for ((parent, call, resume), b) in sink.bypassed.iter().zip(tree.bypassed_calls) {
            assert_eq!((*parent, call.seq, call.pc, resume.seq), (b.parent_id.unwrap(), b.call_seq, b.call_pc, b.resume_seq));
        }
    }
    #[test] fn existing_resolver_equivalence() {
        // Gaps represent special lines; nested, recursive same-site bypass,
        // actual resume, and unresolved outer/inner truncation.
        compare(&[(0,0x100,true),(2,0x200,false),(3,0x204,true),(5,0x300,false),
            (6,0x304,false),(8,0x208,false),(9,0x104,false)], 10);
        compare(&[(0,0x100,true),(1,0x100,true),(3,0x104,false),(4,0x108,false),(5,0x104,false)], 6);
        compare(&[(0,0x100,true),(2,0x200,true),(4,0x300,false)], 7);
        compare(&[(0,0x100,true)], 1);
        compare(&[(0,0x100,true),(3,0x104,false)], 4);
    }
    #[test] fn explicit_depth_and_sink_failure() {
        let mut r = OwnershipResolver::new(1).unwrap(); let mut s = Sink::default();
        r.on_call(InsnFact::new(0,0x100), &mut s).unwrap();
        r.on_insn(InsnFact::new(1,0x200), &mut s).unwrap();
        r.on_call(InsnFact::new(1,0x200), &mut s).unwrap();
        assert!(r.on_insn(InsnFact::new(2,0x300), &mut s).is_err());
        struct Fail;
        impl OwnershipSink for Fail { fn event(&mut self, _: OwnershipEvent) -> Result<()> { Err(TraceError::Cancelled) } }
        let mut r = OwnershipResolver::new(1).unwrap();
        r.on_call(InsnFact::new(0,0x100), &mut Fail).unwrap();
        assert!(matches!(r.on_insn(InsnFact::new(1,0x200), &mut Fail), Err(TraceError::Cancelled)));
        assert!(r.on_call(InsnFact::new(0,u64::MAX), &mut Fail).is_err());
    }
}
