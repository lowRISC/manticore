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
        $req_kw:tt Request $(<$req_lt:lifetime>)? {
            $($req_fields:tt)*
        }

        fn Request::from_wire($r_req:tt, $a_req:tt) $req_from:block

        fn Request::to_wire(&$self_req:tt, $w_req:tt) $req_to:block

        $(
            $(#[$rsp_meta:meta])*
            $rsp_kw:tt Response $(<$rsp_lt:lifetime>)? {
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
            #[cfg(feature = "serde")]
            use serde::{Deserialize, Serialize};

            $(#[$cmd_meta])*
            #[doc = "Corresponds to [`" $CommandType "::" $TYPE "`]."]
            pub enum $Command {}

            impl<'wire> Command<'wire> for $Command {
                type Req = protocol_struct!(@internal if_nonempty ($($req_lt)?) {
                    [<$Command Request>]<'wire>
                } else {
                    [<$Command Request>]
                });
                type Resp = protocol_struct!(@internal if_nonempty ($($rsp_kw)?) {
                    protocol_struct!(@internal if_nonempty ($($($rsp_lt)?)?) {
                        [<$Command Response>]<'wire>
                    } else {
                        [<$Command Response>]
                    })
                } else {
                    i32
                });
                type Error = protocol_struct!(@internal if_nonempty ($($Error)?) {
                    $($Error)?
                } else {
                    NoSpecificError
                });
            }

            make_fuzz_safe! {
                #[doc = "The [`" $Command "`] request."]
                #[derive(Clone, Copy, PartialEq, Eq, Debug)]
                #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
                $(#[$req_meta])*
                pub $req_kw [<$Command Request>] $(<$req_lt>)? {
                    $($req_fields)*
                }
            }

            impl<'wire> Request<'wire> for protocol_struct!(@internal if_nonempty ($($req_lt)?) {
                [<$Command Request>]<'wire>
            } else {
                [<$Command Request>]
            }) {
                const TYPE: $CommandType = $CommandType::$TYPE;
            }

            impl<'wire> FromWire<'wire> for protocol_struct!(@internal if_nonempty ($($req_lt)?) {
                [<$Command Request>]<'wire>
            } else {
                [<$Command Request>]
            }) {
                fn from_wire<R: ReadZero<'wire> + ?Sized, A: Arena>(
                    $r_req: &mut R,
                    $a_req: &'wire A,
                ) -> Result<Self, wire::Error> {
                    $req_from
                }
            }

            impl ToWire for protocol_struct!(@internal if_nonempty ($($req_lt)?) {
                [<$Command Request>]<'_>
            } else {
                [<$Command Request>]
            }) {
                fn to_wire<W: Write>(&$self_req, mut $w_req: W) -> Result<(), wire::Error> {
                    $req_to
                }
            }

            $(
                make_fuzz_safe! {
                    #[doc = "The [`" $Command "`] rspuest."]
                    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
                    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
                    $(#[$rsp_meta])*
                    pub $rsp_kw [<$Command Response>] $(<$rsp_lt>)? {
                        $($rsp_fields)*
                    }
                }

                impl<'wire> Response<'wire> for protocol_struct!(@internal if_nonempty ($($rsp_lt)?) {
                    [<$Command Response>]<'wire>
                } else {
                    [<$Command Response>]
                }) {
                    const TYPE: $CommandType = $CommandType::$TYPE;
                }

                impl<'wire> FromWire<'wire> for protocol_struct!(@internal if_nonempty ($($rsp_lt)?) {
                    [<$Command Response>]<'wire>
                } else {
                    [<$Command Response>]
                }) {
                    fn from_wire<R: ReadZero<'wire> + ?Sized, A: Arena>(
                        $r_rsp: &mut R,
                        $a_rsp: &'wire A,
                    ) -> Result<Self, wire::Error> {
                        $rsp_from
                    }
                }

                impl ToWire for protocol_struct!(@internal if_nonempty ($($rsp_lt)?) {
                    [<$Command Response>]<'_>
                } else {
                    [<$Command Response>]
                }) {
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
