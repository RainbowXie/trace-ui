//! Incidental printed SP prestate is not a stack lifecycle operation. Actual
//! operands, decoded DEF/USE and unexplained poststate changes still demand one.
use trace_parser::types::RegId;
pub(super) fn instruction_requires_frame(raw:&str)->bool {
 let Some((_,operand))=trace_parser::strict_memory::instruction_parts(raw) else{return true;};
 if operand.split(|c:char|!c.is_ascii_alphanumeric()).any(|word|word=="sp"){return true;}
 let parsed=if raw.contains("!0x"){trace_parser::gumtrace::parse_line_gumtrace_full(raw)}else{trace_parser::parser::parse_line_full(raw)};
 let Some(parsed)=parsed else{return true;};
 let (defs,uses)=trace_parser::def_use::determine_def_use(trace_parser::insn_class::classify_and_refine(&parsed),&parsed);
 if defs.contains(&RegId::SP) || uses.contains(&RegId::SP) || parsed.base_reg==Some(RegId::SP){return true;}
 let pre=trace_parser::strict_memory::observed_register_value(raw,"sp",false);
 let post=trace_parser::strict_memory::observed_register_value(raw,"sp",true);
 let has_post_sp=has_post_sp(raw);
 has_post_sp && (post.is_none() || pre.is_none() || pre!=post)
}
pub(super) fn has_post_sp(raw:&str)->bool {
 raw.split_once(" -> ").or_else(||raw.split_once(" => "))
  .is_some_and(|(_,post)|post.split(|c:char|c.is_whitespace() || c==',' || c==';').any(|token|token.starts_with("sp=")))
}
#[cfg(test)]mod tests {
 #[test]fn all_operands_and_post_observations_are_distinguished(){
  for instruction in ["add x20, x21, sp; sp=0x9000", "mystery x20, sp; sp=0x9000", "nop; sp=0x9000 -> sp=bad", "nop; -> sp=0x9000"] {assert!(super::instruction_requires_frame(&format!("[App] 0x100!0x100 {instruction}")));}
  assert!(!super::instruction_requires_frame("[App] 0x100!0x100 nop; sp=0x9000 -> sp=0x9000"));
 }
}
