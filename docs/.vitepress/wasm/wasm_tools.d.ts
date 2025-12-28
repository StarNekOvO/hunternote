/* tslint:disable */
/* eslint-disable */

export function calc_address(base: string, offset: string): string;

export function convert_base(value: string, from_base: number): string;

export function date_to_timestamp(year: number, month: number, day: number, hours: number, minutes: number, seconds: number): bigint;

export function decimal_to_ip(decimal: number): string;

export function decode_base64(input: string): Uint8Array;

export function decode_hex(input: string): Uint8Array;

export function encode_base64(data: Uint8Array): string;

export function encode_hex(data: Uint8Array): string;

export function format_shellcode(input: string, format: string): string;

export function generate_cyclic(length: number): string;

export function generate_padding(length: number, pattern: string): string;

export function get_ip_class(ip: string): string;

export function hash_md5(data: Uint8Array): string;

export function hash_sha1(data: Uint8Array): string;

export function hash_sha256(data: Uint8Array): string;

export function hash_sha512(data: Uint8Array): string;

export function ip_to_binary(ip: string): string;

export function ip_to_decimal(ip: string): number;

export function ip_to_hex(ip: string): string;

export function is_private_ip(ip: string): boolean;

export function parse_cidr(cidr: string): string;

export function shellcode_length(input: string): number;

export function timestamp_to_date(ts: number): string;

export function to_big_endian(value: string, bytes: number): string;

export function to_little_endian(value: string, bytes: number): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly calc_address: (a: number, b: number, c: number, d: number) => [number, number, number, number];
  readonly convert_base: (a: number, b: number, c: number) => [number, number, number, number];
  readonly date_to_timestamp: (a: number, b: number, c: number, d: number, e: number, f: number) => bigint;
  readonly decimal_to_ip: (a: number) => [number, number];
  readonly decode_base64: (a: number, b: number) => [number, number, number, number];
  readonly decode_hex: (a: number, b: number) => [number, number, number, number];
  readonly encode_base64: (a: number, b: number) => [number, number];
  readonly encode_hex: (a: number, b: number) => [number, number];
  readonly format_shellcode: (a: number, b: number, c: number, d: number) => [number, number];
  readonly generate_cyclic: (a: number) => [number, number];
  readonly generate_padding: (a: number, b: number) => [number, number];
  readonly get_ip_class: (a: number, b: number) => [number, number, number, number];
  readonly hash_md5: (a: number, b: number) => [number, number];
  readonly hash_sha1: (a: number, b: number) => [number, number];
  readonly hash_sha256: (a: number, b: number) => [number, number];
  readonly hash_sha512: (a: number, b: number) => [number, number];
  readonly ip_to_binary: (a: number, b: number) => [number, number, number, number];
  readonly ip_to_decimal: (a: number, b: number) => [number, number, number];
  readonly ip_to_hex: (a: number, b: number) => [number, number, number, number];
  readonly is_private_ip: (a: number, b: number) => [number, number, number];
  readonly parse_cidr: (a: number, b: number) => [number, number, number, number];
  readonly shellcode_length: (a: number, b: number) => number;
  readonly timestamp_to_date: (a: number) => [number, number];
  readonly to_big_endian: (a: number, b: number, c: number) => [number, number, number, number];
  readonly to_little_endian: (a: number, b: number, c: number) => [number, number, number, number];
  readonly __wbindgen_externrefs: WebAssembly.Table;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
