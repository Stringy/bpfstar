(* BPFStar.Core -- CO-RE (Compile Once, Run Everywhere) support.

   Models BPF CO-RE field access using typed paths through
   kernel structs. User programmes define the fields they need
   and compose them into paths. The extraction plugin emits
   BPF_CORE_READ() macro calls.

   Field definitions are axioms -- the user asserts that a
   field exists with a given type on a given kernel struct.
   This is a kernel-version-dependent fact; use
   bpf_core_field_exists at runtime for portability.

   Example usage:

     (* Define fields *)
     let f_inode : field KFile KInode = mk_field "f_inode"
     let i_ino   : field KInode UInt64.t = mk_field "i_ino"

     (* Compose a path *)
     let file_ino : core_path KFile UInt64.t =
       Step f_inode (Leaf i_ino)

     (* Read in a Pulse function *)
     fn get_ino (file: kptr KFile)
       requires emp
       returns ino: UInt64.t
       ensures emp
     {
       core_read file file_ino
     }

   Extracts to:
     u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
*)
module BPFStar.Core

open Pulse.Lib.Pervasives
open BPFStar.Types
open BPFStar.KPtr

(* --- Field descriptors ---

   A field s t represents a field on kernel struct s with
   value type t. If t is a kptr, the field is a pointer to
   another kernel struct (used for intermediate path steps).
   If t is a scalar, the field is a leaf value.

   The field_name string drives extraction -- the plugin
   uses it to generate the C field accessor. *)

val field (s: kernel_struct) (t: Type0) : Type0

(* Create a field descriptor. The name must match the
   kernel struct field name exactly. *)
val mk_field (#s: kernel_struct) (#t: Type0) (name: string) : field s t

(* --- Core paths ---

   A path through kernel structs, from source struct s
   to result type t. Each Step follows a pointer field
   to another struct. Leaf reads a scalar field.

   The path type is indexed by the source struct and
   result type, ensuring type safety at verification time. *)

(* Intermediate step: a pointer field linking two kernel structs. *)
noeq
type core_step =
  | MkStep : s1:kernel_struct -> s2:kernel_struct
           -> field s1 (kptr s2) -> core_step

(* A path is a list of intermediate steps plus a final leaf. *)
val core_path (s: kernel_struct) (t: Type0) : Type0

(* Leaf: read a single field directly *)
val leaf (#s: kernel_struct) (#t: Type0)
  (f: field s t) : core_path s t

(* Step: follow a pointer field, then continue along a path *)
val step (#s1: kernel_struct) (#s2: kernel_struct) (#t: Type0)
  (f: field s1 (kptr s2)) (rest: core_path s2 t) : core_path s1 t

(* --- Read operations --- *)

(* Read a value by following a CO-RE path.
   Extracts to BPF_CORE_READ(ptr, field1, ..., fieldN). *)
val core_read (#s: kernel_struct) (#t: Type0)
  (ptr: kptr s) (path: core_path s t)
  : stt t emp (fun _ -> emp)

(* Read a value into a caller-owned buffer.
   Extracts to BPF_CORE_READ_INTO(dst, ptr, field1, ..., fieldN). *)
val core_read_into (#s: kernel_struct) (#t: Type0)
  (ptr: kptr s) (path: core_path s t) (dst: ref t)
  (#v: FStar.Ghost.erased t)
  : stt bpf_ret
    (requires pts_to dst v)
    (ensures fun _ -> exists* v'. pts_to dst v')

(* Read a string field into a buffer.
   Uses bpf_core_read_str for the final field.
   Extracts to BPF_CORE_READ_STR_INTO(dst, ptr, field1, ..., fieldN).
   Returns positive (bytes read including NUL) on success,
   negative on error. *)
val core_read_str (#s: kernel_struct)
  (ptr: kptr s) (path: core_path s (kptr KCharBuf))
  (dst: Pulse.Lib.Array.array UInt8.t)
  (size: UInt32.t{UInt32.v size = Pulse.Lib.Array.length dst})
  : stt bpf_ret
    (requires exists* v. Pulse.Lib.Array.pts_to dst v)
    (ensures fun r -> exists* v'. Pulse.Lib.Array.pts_to dst v' **
      pure (is_positive r \/ is_err r))

(* --- Field existence check ---

   Returns true if the field exists in the running kernel's
   BTF. Use this for kernel-version portability.
   Extracts to bpf_core_field_exists(). *)
val core_field_exists (#s: kernel_struct) (#t: Type0)
  (f: field s t)
  : stt bool emp (fun _ -> emp)
