// SPDX-License-Identifier: GPL-3.0-or-later
//! Generate conservative entry recognition from the actual dispatch arms.
//! A guarded numeric arm still owns that number. Only explicitly dynamic arms
//! use their predicate during recognition; those predicates must be pure ABI tests.

#[macro_export]
macro_rules! syscall_dispatch {
    (number $number:ident, args $args:ident;
     $(#[$attr:meta])* $vis:vis fn $name:ident $params:tt -> $result:ty;
     $known_vis:vis fn $known:ident;
     { $($arms:tt)* }) => {
        $crate::syscall_dispatch!(@collect
            [$number $args] [$(#[$attr])* $vis fn $name $params -> $result] [$known_vis fn $known]
            [] [] [] ; $($arms)*);
    };
    (@collect $ids:tt $function:tt $known:tt
     [$($body:tt)*] [$($patterns:pat,)*] [$($tests:expr,)*] ;
     @dynamic $binding:ident if $guard:expr => $value:expr, $($rest:tt)*) => {
        $crate::syscall_dispatch!(@collect $ids $function $known
            [$($body)* $binding if $guard => $value,]
            [$($patterns,)*] [$($tests,)* $guard,] ; $($rest)*);
    };
    (@collect $ids:tt $function:tt $known:tt
     [$($body:tt)*] [$($patterns:pat,)*] [$($tests:expr,)*] ;
     @fallback => $value:expr $(,)?) => {
        $crate::syscall_dispatch!(@emit $ids $function $known
            [$($body)* _ => $value,] [$($patterns,)*] [$($tests,)*]);
    };
    (@collect $ids:tt $function:tt $known:tt
     [$($body:tt)*] [$($patterns:pat,)*] [$($tests:expr,)*] ;
     $pattern:pat $(if $guard:expr)? => $value:expr, $($rest:tt)*) => {
        $crate::syscall_dispatch!(@collect $ids $function $known
            [$($body)* $pattern $(if $guard)? => $value,]
            [$($patterns,)* $pattern,] [$($tests,)*] ; $($rest)*);
    };
    (@emit [$number:ident $args:ident]
     [$(#[$attr:meta])* $vis:vis fn $name:ident $params:tt -> $result:ty]
     [$known_vis:vis fn $known:ident]
     [$($body:tt)*] [$($patterns:pat,)*] [$($tests:expr,)*]) => {
        $(#[$attr])*
        $vis fn $name $params -> $result {
            match $number { $($body)* }
        }
        // Numeric guards are deliberately conservative. Repeated guarded arms
        // can overlap after dropping their guards; bindings only name the number.
        #[allow(unreachable_patterns, unused_variables)]
        $known_vis fn $known($number: u32, $args: [u64; 6]) -> bool {
            false $(|| matches!($number, $patterns))* $(|| $tests)*
        }
    };
}

#[cfg(test)]
mod tests {
    struct Dispatcher;
    impl Dispatcher {
        syscall_dispatch! {
            number number, args args;
            fn call(&self, number: u32, args: [u64; 6]) -> u64;
            fn recognizes;
            {
                1 if args[0] == 2 => 10,
                1 => 11,
                n @ 4..=6 => n as u64,
                @dynamic number if number == 9 && args[0] == 3 => 90,
                @fallback => 38,
            }
        }
    }
    #[test]
    fn guarded_numeric_and_dynamic_entries_are_generated_with_the_actual_dispatch() {
        let dispatcher = Dispatcher;
        assert_eq!(dispatcher.call(1, [0; 6]), 11);
        assert_eq!(dispatcher.call(1, [2; 6]), 10);
        assert!(Dispatcher::recognizes(1, [0; 6]));
        for n in 4..=6 {
            assert_eq!(dispatcher.call(n, [0; 6]), n as u64);
            assert!(Dispatcher::recognizes(n, [0; 6]));
        }
        assert!(!Dispatcher::recognizes(9, [0; 6]));
        assert!(Dispatcher::recognizes(9, [3; 6]));
        assert_eq!(dispatcher.call(9, [3; 6]), 90);
        for n in [0, 2, 3, 7, 8, u32::MAX] {
            assert_eq!(dispatcher.call(n, [0; 6]), 38);
            assert!(!Dispatcher::recognizes(n, [0; 6]));
        }
    }
}
