use super::proc::Proc;
use super::raw_types;
use super::value::Value;
use crate::runtime::DMResult;
use detour::RawDetour;
use std::collections::{hash_map::Entry, HashMap};
use ahash::RandomState;
use std::ffi::c_void;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::cell::RefCell;

#[doc(hidden)]
pub struct CompileTimeHook {
	pub proc_path: &'static str,
	pub hook: ProcHook,
}

impl CompileTimeHook {
	pub fn new(proc_path: &'static str, hook: ProcHook) -> Self {
		CompileTimeHook { proc_path, hook }
	}
}

inventory::collect!(CompileTimeHook);

// TODO: This is super deceptively named
#[doc(hidden)]
pub struct RuntimeHook(pub fn(&str));
inventory::collect!(RuntimeHook);

extern "C" {
	static mut call_proc_by_id_original: *const c_void;

	#[cfg(unix)]
	static mut call_proc_by_id_original2: *const c_void;

	static mut runtime_original: *const c_void;
	fn runtime_hook(error: *const c_char);

	fn call_proc_by_id_hook_trampoline(
		usr: raw_types::values::Value,
		proc_type: u32,
		proc_id: raw_types::procs::ProcId,
		unk_0: u32,
		src: raw_types::values::Value,
		args: *mut raw_types::values::Value,
		args_count_l: usize,
		unk_1: u32,
		unk_2: u32,
	) -> raw_types::values::Value;

	#[cfg(unix)]
	fn call_proc_by_id_hook_trampoline2(
		out: *mut raw_types::values::Value,
		usr: raw_types::values::Value,
		proc_type: u32,
		proc_id: raw_types::procs::ProcId,
		unk_0: u32,
		src: raw_types::values::Value,
		args: *mut raw_types::values::Value,
		args_count_l: usize,
		unk_1: u32,
		unk_2: u32,
	) -> *mut raw_types::values::Value;
}

pub enum HookFailure {
	NotInitialized,
	ProcNotFound,
	AlreadyHooked,
	UnknownFailure,
}

impl std::fmt::Debug for HookFailure {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::NotInitialized => write!(f, "Library not initialized"),
			Self::ProcNotFound => write!(f, "Proc not found"),
			Self::AlreadyHooked => write!(f, "Proc is already hooked"),
			Self::UnknownFailure => write!(f, "Unknown failure"),
		}
	}
}

pub fn init() -> Result<(), String> {
	unsafe {
		let runtime_hook = RawDetour::new(
			raw_types::funcs::runtime_byond as *const (),
			runtime_hook as *const (),
		)
		.unwrap();

		runtime_hook.enable().unwrap();
		runtime_original = std::mem::transmute(runtime_hook.trampoline());
		std::mem::forget(runtime_hook);
		{
			let call_hook = RawDetour::new(
				raw_types::funcs::call_proc_by_id_byond as *const (),
				call_proc_by_id_hook_trampoline as *const (),
			)
				.unwrap();

			call_hook.enable().unwrap();
			call_proc_by_id_original = std::mem::transmute(call_hook.trampoline());
			std::mem::forget(call_hook);
		}

		#[cfg(unix)]
		{
			let call_hook = RawDetour::new(
				raw_types::funcs::call_proc_by_id2_byond as *const (),
				call_proc_by_id_hook_trampoline2 as *const (),
			)
				.unwrap();

			call_hook.enable().unwrap();
			call_proc_by_id_original2 = std::mem::transmute(call_hook.trampoline());
			std::mem::forget(call_hook);
		}
	}
	Ok(())
}

pub type ProcHook = fn(&Value, &Value, &mut Vec<Value>) -> DMResult;

pub type ByondProcFunc = unsafe extern "C" fn(out: *mut raw_types::values::Value, usr: raw_types::values::Value, src: raw_types::values::Value, args: *mut raw_types::values::Value, arg_count: u32) -> ();

static mut PROC_HOOKS: Option<HashMap<raw_types::procs::ProcId, ProcHook, RandomState>> = None;
static mut CALL_COUNT: Option<HashMap<raw_types::procs::ProcId, u32, RandomState>> = None;

fn hook_by_id(id: raw_types::procs::ProcId, hook: ProcHook) -> Result<(), HookFailure> {
	match unsafe {
		PROC_HOOKS.get_or_insert_with(|| HashMap::with_hasher(RandomState::default()))
	}
	.entry(id)
	{
		Entry::Vacant(v) => {
			v.insert(hook);
			Ok(())
		}
		Entry::Occupied(_) => Err(HookFailure::AlreadyHooked),
	}
}

pub fn clear_hooks() {
	unsafe {
	PROC_HOOKS = None;
	}
}

pub fn hook<S: Into<String>>(name: S, hook: ProcHook) -> Result<(), HookFailure> {
	match super::proc::get_proc(name) {
		Some(p) => hook_by_id(p.id, hook),
		None => Err(HookFailure::ProcNotFound),
	}
}

pub fn chad_hook<S: Into<String>>(name: S, hook: ByondProcFunc) -> Result<(), HookFailure> {
	match super::proc::get_proc(name) {
		Some(p) => {
			chad_hook_by_id(p.id, hook);
			Ok(())
		},
		None => Err(HookFailure::ProcNotFound),
	}
}

pub fn chad_hook_by_id(id: raw_types::procs::ProcId, hook: ByondProcFunc) {
	unsafe {
		let mut hooks = CHAD_HOOKS.borrow_mut();
		let idx = id.0 as usize;
		if idx >= hooks.len() {
			hooks.resize((idx + 1) as usize, None);
		}
		hooks[idx] = Some(hook);
	}
}

impl Proc {
	pub fn hook(&self, func: ProcHook) -> Result<(), HookFailure> {
		hook_by_id(self.id, func)
	}
}

#[no_mangle]
extern "C" fn on_runtime(error: *const c_char) {
	let str = unsafe { CStr::from_ptr(error) }.to_string_lossy();

	for func in inventory::iter::<RuntimeHook> {
		func.0(&str);
	}
}

pub struct CallCount {
	pub proc: Proc,
	pub count: u32
}

pub fn call_counts() -> Option<Vec<CallCount>> {
	unsafe {
		return Some(CALL_COUNT
				.get_or_insert_with(|| HashMap::with_hasher(RandomState::default()))
				.iter()
				.filter_map(|(id, val)|
			if let Some(proc) = Proc::from_id(*id) {
				Some(CallCount { proc: proc, count: *val })
			} else {
				None
			}
		).collect::<Vec<_>>());
	}
}

pub static mut ENABLE_CALL_COUNTS: bool = false;
pub static mut ENABLE_CHAD_HOOKS: bool = true;
pub static mut CHAD_HOOKS: RefCell<Vec<Option<ByondProcFunc>>> = RefCell::new(Vec::new());


#[no_mangle]
extern "C" fn call_proc_by_id_hook(
	ret: *mut raw_types::values::Value,
	usr_raw: raw_types::values::Value,
	_proc_type: u32,
	proc_id: raw_types::procs::ProcId,
	_unknown1: u32,
	src_raw: raw_types::values::Value,
	args_ptr: *mut raw_types::values::Value,
	num_args: usize,
	_unknown2: u32,
	_unknown3: u32,
) -> u8 {

	if unsafe { ENABLE_CHAD_HOOKS } {
		let hooks = unsafe {
			CHAD_HOOKS.borrow()
		};
		if let Some(hook) = hooks.get(proc_id.0 as usize) {
			if let Some(hook) = hook {
				unsafe { hook(ret, src_raw, usr_raw, args_ptr, num_args as u32) };
				return 1;
			}
		}
	}

	if unsafe { ENABLE_CALL_COUNTS } {
		unsafe {
			*CALL_COUNT.get_or_insert_with(|| HashMap::with_hasher(RandomState::default())).entry(proc_id).or_default() += 1
		}
	}

	unsafe { PROC_HOOKS.as_ref() }
		.and_then(|hooks| hooks.get(&proc_id))
		.map(|hook| {
			let src;
			let usr;
			let mut args: Vec<Value>;

			unsafe {
				src = Value::from_raw(src_raw);
				usr = Value::from_raw(usr_raw);

				// Taking ownership of args here
				args = std::slice::from_raw_parts(args_ptr, num_args)
					.iter()
					.map(|v| Value::from_raw_owned(*v))
					.collect();
			}

			let result = hook(&src, &usr, &mut args);

			match result {
				Ok(r) => {
					let result_raw = (&r).raw;
					// Stealing our reference out of the Value
					std::mem::forget(r);
					result_raw
				}
				Err(e) => {
					// TODO: Some info about the hook would be useful (as the hook is never part of byond's stack, the runtime won't show it.)
					Proc::find("/proc/auxtools_stack_trace")
						.unwrap()
						.call(&[&Value::from_string(e.message.as_str()).unwrap()])
						.unwrap();
					Value::null().raw
				}
			}
		})
		.map_or(0, |result| {
			unsafe {
				*ret = result;
			}
			1
		})
}
