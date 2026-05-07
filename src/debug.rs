pub const DEBUG: bool = false;

#[macro_export]
macro_rules! debugln {
    ($($arg:tt)*) => {
        if crate::debug::DEBUG {
            println!($($arg)*);
        }
    };
}

#[macro_export]
macro_rules! debugerr {
    ($($arg:tt)*) => {
        if crate::debug::DEBUG {
            eprintln!($($arg)*);
        }
    };
}
