use super::misc;
use super::strings;
use super::values;
use std::ffi::c_void;

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct ProcId(pub u32);

#[repr(C)]
#[derive(Debug)]
pub struct ProcEntry {
	pub path: strings::StringId, // 0x0
	pub name: strings::StringId, // 0x4
	pub desc: strings::StringId, // 0x8
	pub category: strings::StringId, // 0xC
	flags: u32, // 0x10
	unk_1: u32, // 0x14
	pub bytecode: misc::BytecodeId, //18
	pub locals: misc::LocalsId, // 1C
	pub parameters: misc::ParametersId // 20,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ArgAndLocalStore {
	pub data_store: [values::Value; 10usize],
	pub internal_arg_count: u32,
	pub external_arg_count: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ProcInstance {
	pub proc: ProcId,
	pub flags: u8,
	pub mega_hack: u16,
	pub usr: values::Value,
	pub src: values::Value,
	pub context: *mut ExecutionContext,
	pub arglist_idx: values::ValueData,
	pub callback: *const c_void,
	pub callback_value: u32,
	pub args_count: u32,
	pub args: *mut values::Value,
	pub data_store: ArgAndLocalStore,
	pub time_to_resume: f32,
}

#[repr(C)]
#[derive(Debug)]
pub struct ThrowHandler {
	bytecode_offset: u16,
	next_bytecode: u16,
	next_handler: *mut ThrowHandler
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Timeval {
	tv_sec: u64,
	tv_usec: u64
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IteratorStackValue {
	pub iterator_array: *mut values::Value,
	pub iterator_allocated: u32,
	pub iterator_length: u32,
	pub iterator_index: u32,
	pub iterator_filter_type: values::Value,
	pub iterator_smth: u8,
	pub field_0x19: u8,
	pub iterator_unk1: u16,
	pub next_iterator: *mut IteratorStackValue,
}


#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ExecutionContext {
	pub proc_instance: *mut ProcInstance,
	pub parent_context: *mut ExecutionContext,
	pub filename: strings::StringId,
	pub line: u32,
	pub bytecode: *mut u32,
	pub bytecode_offset: u16,
	pub test_flag: bool,
	pub unused1: u8,
	pub cached_datum: values::Value,
	pub dmvalue_0x20: values::Value,
	pub cached_values: *mut values::Value,
	pub dmvalue_ptr_2c: *mut values::Value,
	pub dot: values::Value,
	pub locals: *mut values::Value,
	pub stack: *mut values::Value,
	pub locals_count: u16,
	pub stack_size: u16,
	pub iterator_stack: *mut IteratorStackValue,
	pub current_iterator: *mut values::Value,
	pub iterator_allocated: u32,
	pub iterator_length: u32,
	pub iterator_index: u32,
	pub iterator_filter_type: values::Value,
	pub iterator_unk1: u32,
	pub jnz_lchk_loop_count: u32,
	pub iterator_smth: u8,
	pub not_suspended: bool,
	pub unk_9: u8,
	pub is_measure_some_time_4: bool,
	pub call_in_progress: bool,
	pub unk_10: u8,
	pub unk_11: u8,
	pub unk_12: u8,
	pub throw_handler: *mut ThrowHandler,
	pub some_time3: Timeval,
	pub some_time2: Timeval,
	pub some_time: Timeval,
	pub some_time4: Timeval,
}


#[repr(C)]
pub struct SuspendedProcsBuffer {
	pub buffer: *mut *mut ProcInstance,
}

#[repr(C)]
pub struct SuspendedProcs {
	pub front: usize,
	pub back: usize,
	pub capacity: usize,
}
