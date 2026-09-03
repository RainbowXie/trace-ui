/// Section-based binary cache format for zero-copy mmap access.
///
/// File layout:
///   [u32 num_sections]
///   [SectionEntry x N]  -- each entry: { offset: u64, length: u64 }
///   [section data, each 8-byte aligned]
///
/// All offsets are absolute (relative to the start of the section table).
#[derive(Default)]
pub struct SectionWriter {
    sections: Vec<(usize, usize)>, // (start_offset_in_buf, byte_length)
    buf: Vec<u8>,
}

impl SectionWriter {
    pub fn new() -> Self {
        Self {
            sections: Vec::new(),
            buf: Vec::new(),
        }
    }

    /// Write a slice of Copy types as a section. Returns section index.
    pub fn write_slice<T: Copy>(&mut self, data: &[T]) -> usize {
        // Align to 8 bytes
        while self.buf.len() % 8 != 0 {
            self.buf.push(0);
        }
        let offset = self.buf.len();
        let byte_len = std::mem::size_of_val(data);
        let ptr = data.as_ptr() as *const u8;
        self.buf
            .extend_from_slice(unsafe { std::slice::from_raw_parts(ptr, byte_len) });
        self.sections.push((offset, byte_len));
        self.sections.len() - 1
    }

    /// Write a single u32 as a section.
    pub fn write_u32(&mut self, val: u32) -> usize {
        self.write_slice(&[val])
    }

    /// Write a single u64 as a section.
    #[allow(dead_code)]
    pub fn write_u64(&mut self, val: u64) -> usize {
        self.write_slice(&[val])
    }

    /// Write raw bytes as a section (for bincode-serialized data like CallTree).
    pub fn write_bytes(&mut self, data: &[u8]) -> usize {
        self.write_slice(data)
    }

    /// Finalize: returns the complete section table + data as bytes.
    /// The caller is responsible for prepending the 64-byte cache header.
    pub fn finish(self) -> Vec<u8> {
        let num_sections = self.sections.len() as u32;
        let raw_table_size = 4 + self.sections.len() * 16; // u32 + N * (u64 offset, u64 length)
                                                           // Pad table to 8-byte alignment so section data stays aligned
        let table_size = (raw_table_size + 7) & !7;

        let mut result = Vec::with_capacity(table_size + self.buf.len());

        // Write section count
        result.extend_from_slice(&num_sections.to_le_bytes());

        // Write section entries (adjust offsets to account for table size)
        for &(offset, length) in &self.sections {
            let abs_offset = (offset + table_size) as u64;
            result.extend_from_slice(&abs_offset.to_le_bytes());
            result.extend_from_slice(&(length as u64).to_le_bytes());
        }

        // Pad table to 8-byte alignment
        while result.len() < table_size {
            result.push(0);
        }

        // Write section data
        result.extend(self.buf);
        result
    }
}

/// Reader for mmap'd section-based cache files.
/// `data` should point to the bytes AFTER the 64-byte cache header.
pub struct SectionReader<'a> {
    data: &'a [u8],
    sections: Vec<(u64, u64)>, // (offset, length) -- offsets relative to start of `data`
}

impl<'a> SectionReader<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let num_sections = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
        let table_end = 4 + num_sections * 16;
        if data.len() < table_end {
            return None;
        }

        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let base = 4 + i * 16;
            let offset = u64::from_le_bytes(data[base..base + 8].try_into().ok()?);
            let length = u64::from_le_bytes(data[base + 8..base + 16].try_into().ok()?);
            // 损坏/截断缓存防御：section 范围必须落在数据区内。
            // 不校验的话后续 slice 索引会越界 panic（mmap 缓存没有分配器捕获）。
            let offset_us = usize::try_from(offset).ok()?;
            let length_us = usize::try_from(length).ok()?;
            if offset_us.checked_add(length_us)? > data.len() {
                return None;
            }
            sections.push((offset, length));
        }
        Some(Self { data, sections })
    }

    /// 预检：section 能否安全转成 elem_size 字节元素的 typed slice。
    ///
    /// 模型（与写入器 write_slice 的实际保证一致）：
    /// - 对齐：writer 把每个 section 起点对齐到 8 字节（buf.len()%8 补零），
    ///   mmap 基址页对齐，故只需 offset % elem_align == 0（elem_align 取
    ///   类型自身的 align_of，如 FlatMemAccessRecord 是 24 字节/对齐 8）；
    /// - 整除：length 必须是 elem_size 的整数倍（非整除会静默截断）；
    /// - 空数组：合法（writer 可写入空 Vec），返回空切片；单值读取
    ///   走 is_valid_single（length == elem_size），零长和填充长度都拒。
    pub fn is_valid_typed(&self, idx: usize, elem_size: usize) -> bool {
        self.is_valid_typed_align(idx, elem_size, elem_size)
    }

    /// 同上，但对齐要求可不同于 elem_size（元素大小 24 的结构体只需
    /// 8 字节对齐——writer 只保证 8）。单值读取走 is_valid_single。
    pub fn is_valid_typed_align(&self, idx: usize, elem_size: usize, elem_align: usize) -> bool {
        let Some(&(offset, length)) = self.sections.get(idx) else {
            return false;
        };
        let offset = offset as usize;
        let length = length as usize;
        // 零长：合法空数组（对齐/整除平凡成立）
        if length == 0 {
            return true;
        }
        offset % elem_align == 0 && length % elem_size == 0
    }

    /// 单值预检：长度必须恰为 elem_size（u32_val/u64_val 的 [0] 需要）；
    /// 多余字节静默忽略会掩盖布局漂移，零长 [0] 会 panic。
    pub fn is_valid_single(&self, idx: usize, elem_size: usize) -> bool {
        self.is_valid_typed_align(idx, elem_size, elem_size) && self.section_len(idx) == elem_size
    }

    /// section 字节长度。
    pub fn section_len(&self, idx: usize) -> usize {
        self.sections
            .get(idx)
            .map(|&(_, l)| l as usize)
            .unwrap_or(0)
    }

    /// typed slice：调用方必须先用 is_valid_typed 验证本 section
    ///（views_from_sections 预检后构造）。零长 section 返回空切片（合法；
    /// 单值读取 u32_val/u64_val 由 is_valid_single 守护）。
    /// debug_assert 拦截违规：对齐要求是类型自身的 align_of（不是 size_of
    ///——24 字节的 FlatMemAccessRecord 只需 8 字节对齐，writer 也只保证 8）。
    pub fn slice<T: Copy>(&self, idx: usize) -> &'a [T] {
        let (offset, length) = self.sections[idx];
        let bytes = &self.data[offset as usize..(offset + length) as usize];
        let align = std::mem::align_of::<T>() as u64;
        let size = std::mem::size_of::<T>() as u64;
        debug_assert!(length == 0 || (offset % align == 0 && length % size == 0));
        unsafe {
            std::slice::from_raw_parts(
                bytes.as_ptr() as *const T,
                bytes.len() / std::mem::size_of::<T>(),
            )
        }
    }

    /// 单值 u32：is_valid_single 已验 length == 4，[0] 安全。
    pub fn u32_val(&self, idx: usize) -> u32 {
        self.slice::<u32>(idx)[0]
    }

    /// Get a single u64 from a section.
    #[allow(dead_code)]
    pub fn u64_val(&self, idx: usize) -> u64 {
        self.slice::<u64>(idx)[0]
    }

    /// Get section data as raw bytes (for bincode deserialization).
    pub fn bytes(&self, idx: usize) -> &'a [u8] {
        self.slice::<u8>(idx)
    }

    pub fn num_sections(&self) -> usize {
        self.sections.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_u32_slice() {
        let data: Vec<u32> = vec![1, 2, 3, 42, 100];
        let mut w = SectionWriter::new();
        let idx = w.write_slice(&data);
        assert_eq!(idx, 0);
        let bytes = w.finish();

        let r = SectionReader::new(&bytes).unwrap();
        assert_eq!(r.num_sections(), 1);
        let out: &[u32] = r.slice(0);
        assert_eq!(out, &[1, 2, 3, 42, 100]);
    }

    #[test]
    fn test_roundtrip_u64_slice() {
        let data: Vec<u64> = vec![0xDEAD_BEEF, 0xCAFE_BABE];
        let mut w = SectionWriter::new();
        w.write_slice(&data);
        let bytes = w.finish();

        let r = SectionReader::new(&bytes).unwrap();
        let out: &[u64] = r.slice(0);
        assert_eq!(out, &[0xDEAD_BEEF, 0xCAFE_BABE]);
    }

    #[test]
    fn test_roundtrip_single_values() {
        let mut w = SectionWriter::new();
        w.write_u32(42);
        w.write_u64(9999);
        let bytes = w.finish();

        let r = SectionReader::new(&bytes).unwrap();
        assert_eq!(r.num_sections(), 2);
        assert_eq!(r.u32_val(0), 42);
        assert_eq!(r.u64_val(1), 9999);
    }

    #[test]
    fn test_roundtrip_bytes() {
        let data = b"hello world";
        let mut w = SectionWriter::new();
        w.write_bytes(data);
        let bytes = w.finish();

        let r = SectionReader::new(&bytes).unwrap();
        assert_eq!(r.bytes(0), b"hello world");
    }

    #[test]
    fn test_multiple_sections() {
        let mut w = SectionWriter::new();
        w.write_slice(&[1u32, 2, 3]); // 0
        w.write_slice(&[10u64, 20]); // 1
        w.write_u32(99); // 2
        w.write_bytes(b"test"); // 3
        let bytes = w.finish();

        let r = SectionReader::new(&bytes).unwrap();
        assert_eq!(r.num_sections(), 4);
        assert_eq!(r.slice::<u32>(0), &[1, 2, 3]);
        assert_eq!(r.slice::<u64>(1), &[10, 20]);
        assert_eq!(r.u32_val(2), 99);
        assert_eq!(r.bytes(3), b"test");
    }

    #[test]
    fn test_empty_section() {
        let empty: Vec<u32> = vec![];
        let mut w = SectionWriter::new();
        w.write_slice(&empty);
        let bytes = w.finish();

        let r = SectionReader::new(&bytes).unwrap();
        // 空数组 section（len 0）合法（C1 修复语义：writer 可写空 Vec，
        // typed 预检不得误判损坏）：typed slice 返回空；单值读取
        // u32_val 零长 [0] panic 由 is_valid_single 拦截。
        assert!(r.bytes(0).is_empty());
        assert!(r.slice::<u32>(0).is_empty());
        assert!(r.is_valid_typed(0, 4), "空数组合法");
        assert!(!r.is_valid_single(0, 4), "单值读取需要恰好 elem_size");
    }

    #[test]
    fn test_single_rejects_padded_length() {
        // 8 字节的“u32 单值”整除且非零，但后四字节会被静默忽略——
        // 精确长度要求才能拦住布局漂移。
        let mut w = SectionWriter::new();
        w.write_slice(&[1u32, 2]);
        let bytes = w.finish();
        let r = SectionReader::new(&bytes).unwrap();
        assert!(r.is_valid_typed(0, 4));
        assert_eq!(r.section_len(0), 8);
        assert!(!r.is_valid_single(0, 4));
    }

    #[test]
    fn test_invalid_data() {
        assert!(SectionReader::new(&[]).is_none());
        assert!(SectionReader::new(&[0, 0, 0]).is_none());
        // num_sections = 1 but no table data
        assert!(SectionReader::new(&[1, 0, 0, 0]).is_none());
    }
}
