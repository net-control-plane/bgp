// Copyright 2021 Rayhaan Jaufeerally.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use bytes::BytesMut;

pub trait Serializable<A> {
    fn to_wire(&self, buf: &mut BytesMut) -> Result<(), std::io::Error>;
    fn from_wire(buf: &mut BytesMut) -> Result<A, std::io::Error>;
}

pub trait NetlinkAttribute {
    fn attr_type(&self) -> u16;
    fn payload_len(&self) -> u16;
    fn write_payload(&self, buf: &mut BytesMut) -> Result<(), std::io::Error>;
}
