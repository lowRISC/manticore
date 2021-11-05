// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Internal macros that provide a "template" for a protocol struct definition,
//! to help cut down on boilerplate.

macro_rules! protocol_struct {
    (
        $(#[$cmd_meta:meta])*
        type $Command:ident;
        $(type Error = $Error:ty;)?

        const TYPE: $CommandType:ty = $TYPE:ident;

        $(#[$req_meta:meta])*
        $(#[@static($sreq_meta:meta)])*
        $req_kw:ident Request $(<$req_lt:lifetime>)? {
            $($req_fields:tt)*
        }

        fn Request::from_wire($r_req:tt, $a_req:tt) $req_from:block

        fn Request::to_wire(&$self_req:tt, $w_req:tt) $req_to:block

        $(
            $(#[$rsp_meta:meta])*
            $(#[@static($srsp_meta:meta)])*
            $rsp_kw:ident Response $(<$rsp_lt:lifetime>)? {
                $($rsp_fields:tt)*
            }

            fn Response::from_wire($r_rsp:tt, $a_rsp:tt) $rsp_from:block

            fn Response::to_wire(&$self_rsp:tt, $w_rsp:tt) $rsp_to:block
        )*
    ) => {paste::paste!{
        #[allow(unused_imports)]
        mod generated {
            use super::*;
            use $crate::io::ReadZero;
            use $crate::io::Write;
            use $crate::mem::Arena;
            use $crate::protocol::wire;
            use $crate::protocol::wire::FromWire;
            use $crate::protocol::wire::ToWire;
            use $crate::protocol::Command;
            use $crate::protocol::NoSpecificError;
            use $crate::protocol::Request;
            use $crate::protocol::Response;

            #[cfg(feature = "arbitrary-derive")]
            use libfuzzer_sys::arbitrary::{self, Arbitrary};

            $(#[$cmd_meta])*
            #[doc = "Corresponds to [`" $CommandType "::" $TYPE "`]."]
            pub enum $Command {}

            impl<'wire> Command<'wire> for $Command {
                type Req = Req<'wire>;
                type Resp = Resp<'wire>;
                type Error = protocol_struct!(@internal if_nonempty ($($Error)?) {
                    $($Error)?
                } else {
                    NoSpecificError
                });
            }

            protocol_struct!(@internal if_nonempty ($($req_lt)?) {
                derive_borrowed! {
                    #[doc = "The [`" $Command "`] request."]
                    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
                    #[cfg_attr(feature = "serde", derive(serde::Serialize))]
                    $(#[$req_meta])*
                    #[@static(
                        derive(Clone, PartialEq, Eq, Debug),
                        cfg_attr(feature = "serde", derive(serde::Deserialize)),
                        cfg_attr(feature = "arbitrary-derive", derive(Arbitrary)),
                    )]
                    $(#[@static($sreq_meta)])*
                    pub $req_kw [<$Command Request>] $(<$req_lt>)? {
                        $($req_fields)*
                    }
                }
                type Req<'wire> = [<$Command Request>]<'wire>;
            } else {
                derive_borrowed! {
                    #[doc = "The [`" $Command "`] request."]
                    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
                    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
                    #[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
                    $(#[$req_meta])*
                    $(#[@static($sreq_meta)])*
                    pub $req_kw [<$Command Request>] {
                        $($req_fields)*
                    }
                }
                type Req<'wire> = [<$Command Request>];
            });

            impl<'wire> Request<'wire> for Req<'wire> {
                type CommandType = $CommandType;
                const TYPE: $CommandType = $CommandType::$TYPE;
            }

            impl<'wire> FromWire<'wire> for Req<'wire> {
                fn from_wire<R: ReadZero<'wire> + ?Sized>(
                    $r_req: &mut R,
                    $a_req: &'wire dyn Arena,
                ) -> Result<Self, wire::Error> {
                    $req_from
                }
            }

            impl ToWire for Req<'_> {
                fn to_wire<W: Write>(&$self_req, mut $w_req: W) -> Result<(), wire::Error> {
                    $req_to
                }
            }

            $(
                protocol_struct!(@internal if_nonempty ($($rsp_lt)?) {
                    derive_borrowed! {
                        #[doc = "The [`" $Command "`] response."]
                        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
                        #[cfg_attr(feature = "serde", derive(serde::Serialize))]
                        $(#[$rsp_meta])*
                        #[@static(
                            derive(Clone, PartialEq, Eq, Debug),
                            cfg_attr(feature = "serde", derive(serde::Deserialize)),
                            cfg_attr(feature = "arbitrary-derive", derive(Arbitrary)),
                        )]
                        $(#[@static($srsp_meta)])*
                        pub $rsp_kw [<$Command Response>] $(<$rsp_lt>)? {
                            $($rsp_fields)*
                        }
                    }
                    type Resp<'wire> = [<$Command Response>]<'wire>;
                } else {
                    derive_borrowed! {
                        #[doc = "The [`" $Command "`] response."]
                        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
                        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
                        #[cfg_attr(feature = "arbitrary-derive", derive(Arbitrary))]
                        $(#[$rsp_meta])*
                        $(#[@static($srsp_meta)])*
                        pub $rsp_kw [<$Command Response>] {
                            $($rsp_fields)*
                        }
                    }
                    type Resp<'wire> = [<$Command Response>];
                });

                impl<'wire> Response<'wire> for Resp<'wire> {
                    type CommandType = $CommandType;
                    const TYPE: $CommandType = $CommandType::$TYPE;
                }

                impl<'wire> FromWire<'wire> for Resp<'wire> {
                    fn from_wire<R: ReadZero<'wire> + ?Sized>(
                        $r_rsp: &mut R,
                        $a_rsp: &'wire dyn Arena,
                    ) -> Result<Self, wire::Error> {
                        $rsp_from
                    }
                }

                impl ToWire for Resp<'_> {
                    fn to_wire<W: Write>(&$self_rsp, mut $w_rsp: W) -> Result<(), wire::Error> {
                        $rsp_to
                    }
                }
            )*
        }
        pub use generated::*;
    }};

    (@internal if_nonempty () { $($t:tt)* } else { $($f:tt)* }) => {$($f)*};
    (@internal if_nonempty ($($nonempty:tt)+) { $($t:tt)* } else { $($f:tt)* }) => {$($t)*};
}
