// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! A trait for expressing types which can be built by borrowing or cloning from
//! another `'static` type.
//!
//! When the `std` feature is enabled, this module exports [`Borrowed`], which is
//! similar to the [`std::borrow::Borrow`] trait, except that, rather than being
//! implemented on an owned type like `Box<T>` and exposing the ability to borrow
//! it as `&T`, it is implemented on a borrowed type `&'a T`, and specifies how
//! to go from a `&'a Box<T>` to a `&'a T`.
//!
//! This trait is necessary to implement two features on our protocol structs:
//! - Fuzzing. A limitation on Rust fuzzing libraries requires that fuzzed types
//!   be `'static`. Because many protocol structs have lifetimes attached, this
//!   is a non-starter, so we generate `'static` versions from which we can cheaply
//!   derive them.
//! - Deserialization. `serde` does not do a great job of handling complex
//!   non-`'static` types, such as `&[T]` for `T != u8`. We implement `Deserialize`
//!   on the static type instead, and require users to [`Borrowed::borrow()`] it to
//!   get the correct type.
//!
//! [`Borrowed`] is a sealed trait; it is not intended for implementation outside of
//! the crate.

#[allow(unused)]
pub(crate) mod sealed {
    pub trait Sealed {}
}

#[cfg(feature = "std")]
mod cfg_gated {
    use super::sealed::Sealed;

    /// A type which can be built by borrowing from another, `'static` type.
    ///
    /// The resulting borrowed type may capture the lifetime `'a`, although the
    /// "borrowing" operation may also just be a clone under the hood.
    ///
    /// NOTE: This trait is not intended for general consumption, but is
    /// exposed to allow callers to generate protocol messages in an allocating
    /// setting like `serde`. See the [module documentation][super].
    pub trait Borrowed<'a>: Sealed {
        /// The `'static` type that `Self` can be built from
        type Static: 'static;

        /// Borrow `x` as `Self`.
        ///
        /// Although named `borrow`, this operation is permitted to clone
        /// `Static`.
        fn borrow(x: &'a Self::Static) -> Self;
    }

    /// Extracts the `'static` equivalent of `Borrowed`.
    pub type AsStatic<'a, B> = <B as Borrowed<'a>>::Static;

    impl<T: 'static + Sized> Sealed for &T {}
    impl<'a, T: 'static + Sized> Borrowed<'a> for &'a T {
        type Static = T;
        #[inline]
        fn borrow(x: &'a T) -> Self {
            x
        }
    }

    impl<T: 'static + Sized> Sealed for &[T] {}
    impl<'a, T: 'static + Sized> Borrowed<'a> for &'a [T] {
        type Static = Box<[T]>;
        #[inline]
        fn borrow(x: &'a Box<[T]>) -> Self {
            x
        }
    }

    impl Sealed for &str {}
    impl<'a> Borrowed<'a> for &'a str {
        type Static = Box<str>;
        #[inline]
        fn borrow(x: &'a Box<str>) -> Self {
            x
        }
    }

    impl<T: 'static + Clone, const N: usize> Sealed for [T; N] {}
    impl<'a, T: 'static + Clone, const N: usize> Borrowed<'a> for [T; N] {
        type Static = Self;
        #[inline]
        fn borrow(x: &'a Self) -> Self {
            x.clone()
        }
    }

    impl<'a, T: Borrowed<'a>, U: Borrowed<'a>> Sealed for (T, U) {}
    impl<'a, T: Borrowed<'a>, U: Borrowed<'a>> Borrowed<'a> for (T, U) {
        type Static = (T::Static, U::Static);
        #[inline]
        fn borrow((x, y): &'a Self::Static) -> Self {
            (T::borrow(x), U::borrow(y))
        }
    }
}

#[cfg(feature = "std")]
pub use cfg_gated::*;

/// Derives [`Borrowed`] impls for Manticore types.
///
/// This macro provides two syntaces. The first is for implementing [`Borrowed`]
/// on preexisting `Clone + 'static` types via cloning:
/// ```text
/// derive_borrowed!(Foo, Bar, Baz, ...);
/// ```
///
/// The second is intended to forward to the individual fields of an aggregate,
/// when that type has a lifetime. For example:
/// ```text
/// derive_borrowed! {
///     pub struct MyMessage<'a> {
///         foo: u32,
///         bytes: &'a [u8],
///     }
/// }
/// ```
///
/// Because the second form generates a type, any attributes marked
/// `#[@static(...)]` will be applied to the corresponding type, variant, or field
/// in the owned version of the struct. This is useful, for example, for threading
/// through implementations of `Arbitrary` or `serde::Deserialize`, since the borrowed
/// type may not be able to implement them correctly.
///
/// Due to macro parser limitations, the `static` attributes must come after all other
/// attributes. This is also the reason for the unfortunate non-standard syntax. Given
/// this is not an external API, the tradeoff between that and not having to retype
/// all of this boilerplate seems worth it.
macro_rules! derive_borrowed {
    // Implement `Borrowed` on a pre-existing type via `Clone`.
    ($($name:ty),* $(,)?) => {$(
        #[cfg(feature = "std")]
        impl<'a> $crate::protocol::borrowed::Borrowed<'a> for $name
        where
            Self: Clone,
        {
            type Static = $name;
            fn borrow(x: &'a $name) -> Self {
                x.clone()
            }
        }
        impl $crate::protocol::borrowed::sealed::Sealed for $name {}
    )*};

    // Implement `Borrowed` on a type without a lifetime via forwarding to
    // the rule above. This is intended to allow the item-wrapping version
    // to condition on whether or not the type has a lifetime.
    (
        $(#[$meta:meta])*
        $(#[@static($($ometa:meta),* $(,)?)])*
        $vis:vis struct $name:ident {$(
            $(#[$fmeta:meta])*
            $(#[@static($($ofmeta:meta),* $(,)?)])*
            $fvis:vis $field:ident: $ty:ty,
        )*}
    ) => {
        $(#[$meta])*
        $($(#[cfg_attr(feature = "std", $ometa)])*)*
        $vis struct $name {$(
            $(#[$fmeta])*
            $($(#[cfg_attr(feature = "std", $ofmeta)])*)*
            $fvis $field: $ty,
        )*}
        derive_borrowed!($name);
    };

    // Implement `Borrowed` on a type without a lifetime via forwarding to
    // the rule above. This is intended to allow the item-wrapping version
    // to condition on whether or not the type has a lifetime.
    (
        $(#[$meta:meta])*
        $(#[@static($($ometa:meta),* $(,)?)])*
        $vis:vis enum ident {$(
            $(#[$vmeta:meta])*
            $(#[@static($($ovmeta:meta),* $(,)?)])*
            $variant:ident
            $({$(
                $(#[$fmeta:meta])*
                $(#[@static($($ofmeta:meta),* $(,)?)])*
                $field:ident: $ty:ty,
            )*})?,
        )*}
    ) => {
        $(#[$meta])*
        $($(#[cfg_attr(feature = "std", $ometa)])*)*
        $vis enum $name {$(
            $(#[$vmeta])*
            $($(#[cfg_attr(feature = "std", $ovmeta)])*)*
            $variant
            $({$(
                $(#[$fmeta])*
                $($(#[cfg_attr(feature = "std", $ofmeta)])*)*
                $field: $ty,
            )*})?,
        )*}
        derive_borrowed!($name);
    };

    // Implement `Borrowed` on a struct with a lifetime parameter by
    // forwarding to each field's `Borrow` impl.
    (
        $(#[$meta:meta])*
        $(#[@static($($ometa:meta),* $(,)?)])*
        $vis:vis struct $name:ident <$lt:lifetime> {$(
            $(#[$fmeta:meta])*
            $(#[@static($($ofmeta:meta),* $(,)?)])*
            $fvis:vis $field:ident: $ty:ty,
        )*}
    ) => {
        $(#[$meta])*
        $vis struct $name<$lt> {$(
            $(#[$fmeta])*
            $fvis $field: $ty,
        )*}


        #[cfg(feature = "std")]
        const _: () = paste::paste!{{
            use $crate::protocol::borrowed::Borrowed;

            $(
                // The type names may include lifetimes, such as
                // &'wire [u8], so we cannot utter them in the struct
                // below. These type aliases give us a workaround for
                // that.
                type [<$field:camel AsStatic>]<$lt> =
                  <$ty as Borrowed<$lt>>::Static;
            )*

            $($(#[cfg_attr(feature = "std", $ometa)])*)*
            $vis struct [<$name Static>] {$(
                $($(#[cfg_attr(feature = "std", $ofmeta)])*)*
                $fvis $field: [<$field:camel AsStatic>]<'static>,
            )*}
            impl<'a> Borrowed<'a> for $name<'a> {
                type Static = [<$name Static>];
                fn borrow(x: &'a [<$name Static>]) -> Self {
                    $name {$(
                        $field: Borrowed::borrow(&x.$field),
                    )*}
                }
            }
            impl $crate::protocol::borrowed::sealed::Sealed for $name<'_> {}
        }};
    };


    // Implement `Borrowed` on a struct with a lifetime parameter by
    // forwarding to each field's `Borrow` impl.
    (
        $(#[$meta:meta])*
        $(#[@static($($ometa:meta),* $(,)?)])*
        $vis:vis enum $name:ident <$lt:lifetime> {$(
            $(#[$vmeta:meta])*
            $(#[@static($($ovmeta:meta),* $(,)?)])*
            $variant:ident
            $({$(
                $(#[$fmeta:meta])*
                $(#[@static($($ofmeta:meta),* $(,)?)])*
                $field:ident: $ty:ty,
            )*})?,
        )*}
    ) => {
        $(#[$meta])*
        $vis enum $name<$lt> {$(
            $(#[$vmeta])*
            $variant $({$(
                $(#[$fmeta])*
                $field: $ty,
            )*})?,
        )*}


        #[cfg(feature = "std")]
        const _: () = paste::paste!{{
            use $crate::protocol::borrowed::Borrowed;

            $($($(
                // The type names may include lifetimes, such as
                // &'wire [u8], so we cannot utter them in the struct
                // below. These type aliases give us a workaround for
                // that.
                type [<$variant $field:camel AsStatic>]<$lt> =
                  <$ty as Borrowed<$lt>>::Static;
            )*)?)*

            $($(#[cfg_attr(feature = "std", $ometa)])*)*
            $vis enum [<$name Static>] {$(
                $($(#[cfg_attr(feature = "std", $ovmeta)])*)*
                $variant $({$(
                    $($(#[cfg_attr(feature = "std", $ofmeta)])*)*
                    $field: [<$variant $field:camel AsStatic>]<'static>,
                )*})?,
            )*}
            impl<'a> Borrowed<'a> for $name<'a> {
                type Static = [<$name Static>];
                fn borrow(x: &'a [<$name Static>]) -> Self {
                    match x {$(
                        [<$name Static>]::$variant $({
                            $($field),*
                        })? => $name::$variant $({
                                $($field: Borrowed::borrow($field)),*
                        })?,
                    )*}
                }
            }
            impl $crate::protocol::borrowed::sealed::Sealed for $name<'_> {}
        }};
    }
}

derive_borrowed! {
    u8, u16, u32, u64, u128, usize,
    i8, i16, i32, i64, i128, isize,
}
