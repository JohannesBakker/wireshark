/* packet-kdbus.c
 * Routines for kdbus packet disassembly
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 *
 * This file created by Daniel Mack <daniel@zonque.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <string.h>
#include <stdint.h>

#include <linux/kdbus.h>

#include <wiretap/wtap.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/etypes.h>
#include <epan/aftypes.h>

#define KDBUS_CAP_SIZE (2 * 4)
#define KDBUS_ALIGN8(l) (((l) + 7) & ~7)

static dissector_table_t kdbus_dissector_table;

/* protocols and header fields */
static int proto_kdbus = -1;
static int proto_kdbus_item = -1;
static int hf_kdbus_msg_size = -1;
static int hf_kdbus_msg_flags = -1;
static int hf_kdbus_msg_priority = -1;
static int hf_kdbus_msg_dst_id = -1;
static int hf_kdbus_msg_src_id = -1;
static int hf_kdbus_msg_payload_type = -1;
static int hf_kdbus_msg_cookie = -1;
static int hf_kdbus_msg_cookie_reply = -1;
static int hf_kdbus_msg_timeout_ns = -1;
static int hf_kdbus_msg_flag_expect_reply = -1;
static int hf_kdbus_msg_flag_no_auto_start = -1;
static int hf_kdbus_msg_flag_signal = -1;

static int hf_kdbus_item_size = -1;
static int hf_kdbus_item_type = -1;
static int hf_kdbus_item_string = -1;
static int hf_kdbus_item_memfd_size = -1;
static int hf_kdbus_item_memfd_fd = -1;
static int hf_kdbus_item_timestamp_seqnum = -1;
static int hf_kdbus_item_timestamp_monotonic = -1;
static int hf_kdbus_item_timestamp_realtime = -1;
static int hf_kdbus_item_vec_size = -1;
static int hf_kdbus_item_vec_address = -1;
static int hf_kdbus_item_vec_offset = -1;
static int hf_kdbus_item_vec_payload = -1;
static int hf_kdbus_item_creds_uid = -1;
static int hf_kdbus_item_creds_euid = -1;
static int hf_kdbus_item_creds_suid = -1;
static int hf_kdbus_item_creds_fsuid = -1;
static int hf_kdbus_item_creds_gid = -1;
static int hf_kdbus_item_creds_egid = -1;
static int hf_kdbus_item_creds_sgid = -1;
static int hf_kdbus_item_creds_fsgid = -1;
static int hf_kdbus_item_pids_pid = -1;
static int hf_kdbus_item_pids_tid = -1;
static int hf_kdbus_item_pids_ppid = -1;
static int hf_kdbus_item_auxgroup_id = -1;
static int hf_kdbus_item_caps_inheritable = -1;
static int hf_kdbus_item_caps_permitted = -1;
static int hf_kdbus_item_caps_effective = -1;
static int hf_kdbus_item_caps_bset = -1;
static int hf_kdbus_item_bloom = -1;
static int hf_kdbus_item_audit_sessionid = -1;
static int hf_kdbus_item_audit_loginuid = -1;

static int hf_kdbus_name_flag_replace_existing = -1;
static int hf_kdbus_name_flag_allow_replacement = -1;
static int hf_kdbus_name_flag_queue = -1;
static int hf_kdbus_name_flag_in_queue = -1;
static int hf_kdbus_name_flag_activator = -1;

static int hf_kdbus_item_conn_add_flags =-1;
static int hf_kdbus_item_conn_add_id =-1;
static int hf_kdbus_item_conn_remove_flags =-1;
static int hf_kdbus_item_conn_remove_id =-1;
static int hf_kdbus_item_name_change_flags_old =-1;
static int hf_kdbus_item_name_change_id_old =-1;
static int hf_kdbus_item_name_change_flags_new =-1;
static int hf_kdbus_item_name_change_id_new =-1;

static int hf_kdbus_item_cap_chown =-1;
static int hf_kdbus_item_cap_dac_override =-1;
static int hf_kdbus_item_cap_read_search =-1;
static int hf_kdbus_item_cap_fowner =-1;
static int hf_kdbus_item_cap_fsetid =-1;
static int hf_kdbus_item_cap_kill =-1;
static int hf_kdbus_item_cap_setgid =-1;
static int hf_kdbus_item_cap_setuid =-1;
static int hf_kdbus_item_cap_setpcap =-1;
static int hf_kdbus_item_cap_linux_immutable =-1;
static int hf_kdbus_item_cap_bind_service =-1;
static int hf_kdbus_item_cap_net_broadcast =-1;
static int hf_kdbus_item_cap_net_admin =-1;
static int hf_kdbus_item_cap_net_raw =-1;
static int hf_kdbus_item_cap_ipc_clock =-1;
static int hf_kdbus_item_cap_ipc_owner =-1;
static int hf_kdbus_item_cap_sys_module =-1;
static int hf_kdbus_item_cap_sys_rawio =-1;
static int hf_kdbus_item_cap_sys_chroot =-1;
static int hf_kdbus_item_cap_sys_ptrace =-1;
static int hf_kdbus_item_cap_sys_pacct =-1;
static int hf_kdbus_item_cap_sys_admin =-1;
static int hf_kdbus_item_cap_sys_boot =-1;
static int hf_kdbus_item_cap_sys_nice =-1;
static int hf_kdbus_item_cap_sys_resource =-1;
static int hf_kdbus_item_cap_sys_time =-1;
static int hf_kdbus_item_cap_sys_tty_config =-1;
static int hf_kdbus_item_cap_mknod =-1;
static int hf_kdbus_item_cap_lease =-1;
static int hf_kdbus_item_cap_audit_write =-1;
static int hf_kdbus_item_cap_audit_control =-1;
static int hf_kdbus_item_cap_setfcap =-1;
static int hf_kdbus_item_cap_mac_override =-1;
static int hf_kdbus_item_cap_admin =-1;
static int hf_kdbus_item_cap_syslog =-1;
static int hf_kdbus_item_cap_wake_alarm =-1;
static int hf_kdbus_item_cap_block_suspend =-1;

static gint ett_kdbus = -1;
static gint ett_kdbus_item = -1;

static dissector_handle_t item_handle;

static const val64_string payload_types[] = {
	{ KDBUS_PAYLOAD_KERNEL,		"Kernel" },
	{ KDBUS_PAYLOAD_DBUS,		"DBusDBus" },
};

static const val64_string item_types[] = {
	{ _KDBUS_ITEM_NULL,		"NULL" },

	/* Filled in by userspace */
	{ KDBUS_ITEM_PAYLOAD_VEC,	"Payload: data_vec, reference to memory area" },
	{ KDBUS_ITEM_PAYLOAD_OFF,	"Payload: data_vec, reference to memory area" },
	{ KDBUS_ITEM_PAYLOAD_MEMFD,	"Payload: file descriptor of a memfd" },
	{ KDBUS_ITEM_FDS,		"Payload: file descriptor(s)" },
	{ KDBUS_ITEM_BLOOM_PARAMETER,	"Filter: bloom filter parameter" },
	{ KDBUS_ITEM_BLOOM_FILTER,	"Filter: bloom filter filter" },
	{ KDBUS_ITEM_BLOOM_MASK,	"Filter: bloom filter mask" },

	{ KDBUS_ITEM_DST_NAME,		"destination's well-known name" },

	{ KDBUS_ITEM_NAME,		"Metadata: name" },
	{ KDBUS_ITEM_CONN_DESCRIPTION,	"Metadata: connection description" },
	{ KDBUS_ITEM_TIMESTAMP,		"Metadata: timestamp" },
	{ KDBUS_ITEM_CREDS,		"Metadata: task creds" },
	{ KDBUS_ITEM_AUXGROUPS,		"Metadata: auxiliary groups" },
	{ KDBUS_ITEM_PID_COMM,		"Metadata: pid comm" },
	{ KDBUS_ITEM_TID_COMM,		"Metadata: tid comm" },
	{ KDBUS_ITEM_EXE,		"Metadata: executable" },
	{ KDBUS_ITEM_CMDLINE,		"Metadata: command line" },
	{ KDBUS_ITEM_CGROUP,		"Metadata: cgroup path" },
	{ KDBUS_ITEM_CAPS,		"Metadata: capabilities" },
	{ KDBUS_ITEM_SECLABEL,		"Metadata: security label" },
	{ KDBUS_ITEM_AUDIT,		"Metadata: audit" },

	{ KDBUS_ITEM_NAME_ADD,		"Notification: name added" },
	{ KDBUS_ITEM_NAME_REMOVE,	"Notification: name removed" },
	{ KDBUS_ITEM_NAME_CHANGE,	"Notification: name changed" },
	{ KDBUS_ITEM_ID_ADD,		"Notification: connection ID added" },
	{ KDBUS_ITEM_ID_REMOVE,		"Notification: connection ID removed" },
	{ KDBUS_ITEM_REPLY_TIMEOUT,	"Notification: reply timed out" },
	{ KDBUS_ITEM_REPLY_DEAD,	"Notification: reply connection died" },
};

static hf_register_info hf_msg[] = {
	{ &hf_kdbus_msg_size,			{ "Message size",	"kdbus.msg.size",		FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_msg_flags,			{ "Flags",		"kdbus.msg.flags",		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_msg_priority,		{ "Priority",		"kdbus.msg.priority",		FT_INT64,  BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_msg_dst_id,			{ "Destination ID",	"kdbus.msg.dst_id",		FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_msg_src_id,			{ "Source ID",		"kdbus.msg.src_id",		FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_msg_cookie,			{ "Cookie",		"kdbus.msg.cookie",		FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_msg_cookie_reply,		{ "Cookie reply",	"kdbus.msg.cookie_reply",	FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_msg_timeout_ns,		{ "Timeout (ns)",	"kdbus.msg.timeout_ns",		FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_msg_payload_type,		{ "Payload type",	"kdbus.msg.payload_type",	FT_UINT64, BASE_HEX | BASE_VAL64_STRING, VALS(payload_types), 0x0, NULL, HFILL }},

	/* message flags */
	{ &hf_kdbus_msg_flag_expect_reply,	{ "Expect reply",	"kdbus.msg.flags.expect_reply",		FT_BOOLEAN, 64, NULL, KDBUS_MSG_EXPECT_REPLY, NULL, HFILL }},
	{ &hf_kdbus_msg_flag_no_auto_start,	{ "No auto start",	"kdbus.msg.flags.no_auto_start",	FT_BOOLEAN, 64, NULL, KDBUS_MSG_NO_AUTO_START, NULL, HFILL }},
	{ &hf_kdbus_msg_flag_signal,		{ "Signal",		"kdbus.msg.flags.signal",		FT_BOOLEAN, 64, NULL, KDBUS_MSG_SIGNAL, NULL, HFILL }},
};

static hf_register_info hf_item[] = {
	{ &hf_kdbus_item_size,			{ "Size",			"kdbus.item.size",			FT_UINT64, BASE_DEC,  NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_type,			{ "Type",			"kdbus.item.type",			FT_UINT64, BASE_HEX | BASE_VAL64_STRING, VALS(item_types), 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_string,		{ "String value",		"kdbus.item.string",			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_memfd_size,		{ "memfd size",			"kdbus.item.memfd.size",		FT_UINT64, BASE_DEC,  NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_memfd_fd,		{ "memfd fd",			"kdbus.item.memfd.fd",			FT_UINT32, BASE_DEC,  NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_timestamp_seqnum,	{ "Sequence number",		"kdbus.item.timestamp.seqnum",		FT_UINT64, BASE_DEC,  NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_timestamp_monotonic,	{ "Timestamp (monotonic)",	"kdbus.item.timestamp.monotonic_ns",	FT_UINT64, BASE_DEC,  NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_timestamp_realtime,	{ "Timestamp (realtime)",	"kdbus.item.timestamp.realtime_ns",	FT_UINT64, BASE_DEC,  NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_vec_size,		{ "Data vector size",		"kdbus.item.vec.size",			FT_UINT64, BASE_DEC,  NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_vec_address,		{ "Data vector address",	"kdbus.item.vec.address",		FT_UINT64, BASE_HEX,  NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_vec_offset,		{ "Data vector offset",		"kdbus.item.vec.offset",		FT_UINT64, BASE_HEX,  NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_vec_payload,		{ "Data vector payload",	"kdbus.item.vec.payload",		FT_BYTES,  BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_bloom,			{ "Bloom filter data",		"kdbus.item.bloom",			FT_BYTES,  BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_audit_sessionid,	{ "Audit session ID",		"kdbus.item.audit.sessionid",		FT_UINT64, BASE_HEX,  NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_audit_loginuid,	{ "Audit login UID",		"kdbus.item.audit.loginuid",		FT_UINT64, BASE_HEX,  NULL, 0x0, NULL, HFILL }},

	{ &hf_kdbus_name_flag_replace_existing,	{ "Replace existing", "kdbus.item.name.flags.replace_existing",		FT_BOOLEAN, 64, NULL, KDBUS_NAME_REPLACE_EXISTING, NULL, HFILL }},
	{ &hf_kdbus_name_flag_allow_replacement,{ "Allow replacement", "kdbus.item.name.flags.allow_replacement",	FT_BOOLEAN, 64, NULL, KDBUS_NAME_ALLOW_REPLACEMENT, NULL, HFILL }},
	{ &hf_kdbus_name_flag_queue,		{ "Queue", "kdbus.item.name.flags.queue",				FT_BOOLEAN, 64, NULL, KDBUS_NAME_QUEUE, NULL, HFILL }},
	{ &hf_kdbus_name_flag_in_queue,		{ "In queue", "kdbus.item.name.flags.in_queue",				FT_BOOLEAN, 64, NULL, KDBUS_NAME_IN_QUEUE, NULL, HFILL }},
	{ &hf_kdbus_name_flag_activator,	{ "Activator", "kdbus.item.name.flags.activator",			FT_BOOLEAN, 64, NULL, KDBUS_NAME_ACTIVATOR, NULL, HFILL }},

	{ &hf_kdbus_item_creds_uid,		{ "Creds UID",		"kdbus.item.creds.uid",				FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_creds_euid,		{ "Creds EUID",		"kdbus.item.creds.euid",			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_creds_suid,		{ "Creds SUID",		"kdbus.item.creds.suid",			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_creds_fsuid,		{ "Creds FSUID",	"kdbus.item.creds.fsuid",			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_creds_gid,		{ "Creds GID",		"kdbus.item.creds.gid",				FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_creds_egid,		{ "Creds EGID",		"kdbus.item.creds.egid",			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_creds_sgid,		{ "Creds SGID",		"kdbus.item.creds.sgid",			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_creds_fsgid,		{ "Creds FSGID",	"kdbus.item.creds.fsgid",			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},

	{ &hf_kdbus_item_pids_pid,		{ "PID",		"kdbus.item.pids.pid",				FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_pids_tid,		{ "TID",		"kdbus.item.pids.tid",				FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_pids_ppid,		{ "Parent PID",		"kdbus.item.pids.ppid",				FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},

	{ &hf_kdbus_item_auxgroup_id,		{ "Auxiliary group id",	"kdbus.item.auxgroups.id",			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }},

	{ &hf_kdbus_item_conn_add_id,		{ "Connection add notification ID",		"kdbus.item.id_remove.id",	FT_UINT64, BASE_DEC,  NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_conn_add_flags,	{ "Connection add notification flags",		"kdbus.item.id_remove.flags",	FT_UINT64, BASE_HEX,  NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_conn_remove_id,	{ "Connection remove notification ID",		"kdbus.item.id_remove.id",	FT_UINT64, BASE_DEC,  NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_conn_remove_flags,	{ "Connection remove notification flags",	"kdbus.item.id_remove.flags",	FT_UINT64, BASE_HEX,  NULL, 0x0, NULL, HFILL }},

	{ &hf_kdbus_item_name_change_id_old,	{ "Name change connection ID (old)",		"kdbus.item.name_change.id_old",	FT_UINT64, BASE_DEC,  NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_name_change_flags_old,	{ "Name change flags (old)",			"kdbus.item.name_change.flags_old",	FT_UINT64, BASE_HEX,  NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_name_change_id_new,	{ "Name change connection ID (new)",		"kdbus.item.name_change.id_new",	FT_UINT64, BASE_DEC,  NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_name_change_flags_new,	{ "Name change flags (new)",			"kdbus.item.name_change.flags_new",	FT_UINT64, BASE_HEX,  NULL, 0x0, NULL, HFILL }},

	{ &hf_kdbus_item_caps_inheritable,	{ "Caps (inheritable)",	"kdbus.item.caps.inheritable",			FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_caps_permitted,	{ "Caps (permitted)",	"kdbus.item.caps.permitted",			FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_caps_effective,	{ "Caps (effective)",	"kdbus.item.caps.effective",			FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_kdbus_item_caps_bset,		{ "Caps (bset)",	"kdbus.item.caps.bset",				FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

	/* caps u32.0 */
	{ &hf_kdbus_item_cap_chown,		{ "chown", "kdbus.item.cap.chown",					FT_BOOLEAN, 32, NULL, 1 << 0,  NULL, HFILL }},
	{ &hf_kdbus_item_cap_dac_override,	{ "DAC override", "kdbus.item.cap.dac_override",			FT_BOOLEAN, 32, NULL, 1 << 1,  NULL, HFILL }},
	{ &hf_kdbus_item_cap_read_search,	{ "DAC read search", "kdbus.item.cap.dac_read_search",			FT_BOOLEAN, 32, NULL, 1 << 2,  NULL, HFILL }},
	{ &hf_kdbus_item_cap_fowner,		{ "fowner", "kdbus.item.cap.fowner",					FT_BOOLEAN, 32, NULL, 1 << 3,  NULL, HFILL }},
	{ &hf_kdbus_item_cap_fsetid,		{ "fsetid", "kdbus.item.cap.fsetid",					FT_BOOLEAN, 32, NULL, 1 << 4,  NULL, HFILL }},
	{ &hf_kdbus_item_cap_kill,		{ "kill", "kdbus.item.cap.kill",					FT_BOOLEAN, 32, NULL, 1 << 5,  NULL, HFILL }},
	{ &hf_kdbus_item_cap_setgid,		{ "setgid", "kdbus.item.cap.setgid",					FT_BOOLEAN, 32, NULL, 1 << 6,  NULL, HFILL }},
	{ &hf_kdbus_item_cap_setuid,		{ "setuid", "kdbus.item.cap.setuid",					FT_BOOLEAN, 32, NULL, 1 << 7,  NULL, HFILL }},
	{ &hf_kdbus_item_cap_setpcap,		{ "setpcap", "kdbus.item.cap.setpcap",					FT_BOOLEAN, 32, NULL, 1 << 8,  NULL, HFILL }},
	{ &hf_kdbus_item_cap_linux_immutable,	{ "linux immutable", "kdbus.item.cap.linux_immuntable",			FT_BOOLEAN, 32, NULL, 1 << 9,  NULL, HFILL }},
	{ &hf_kdbus_item_cap_bind_service,	{ "bind service", "kdbus.item.cap.bind_service",			FT_BOOLEAN, 32, NULL, 1 << 10, NULL, HFILL }},
	{ &hf_kdbus_item_cap_net_broadcast,	{ "net broadcast", "kdbus.item.cap.net_broadcast",			FT_BOOLEAN, 32, NULL, 1 << 11, NULL, HFILL }},
	{ &hf_kdbus_item_cap_net_admin,		{ "net admin", "kdbus.item.cap.net_admin",				FT_BOOLEAN, 32, NULL, 1 << 12, NULL, HFILL }},
	{ &hf_kdbus_item_cap_net_raw,		{ "net raw", "kdbus.item.cap.net_raw",					FT_BOOLEAN, 32, NULL, 1 << 13, NULL, HFILL }},
	{ &hf_kdbus_item_cap_ipc_clock,		{ "ipc clock", "kdbus.item.cap.ipc_clock",				FT_BOOLEAN, 32, NULL, 1 << 14, NULL, HFILL }},
	{ &hf_kdbus_item_cap_ipc_owner,		{ "ipc owner", "kdbus.item.cap.ipc_owner",				FT_BOOLEAN, 32, NULL, 1 << 15, NULL, HFILL }},
	{ &hf_kdbus_item_cap_sys_module,	{ "sys module", "kdbus.item.cap.sys_module",				FT_BOOLEAN, 32, NULL, 1 << 16, NULL, HFILL }},
	{ &hf_kdbus_item_cap_sys_rawio,		{ "sys raw i/o", "kdbus.item.cap.sys_rawio",				FT_BOOLEAN, 32, NULL, 1 << 17, NULL, HFILL }},
	{ &hf_kdbus_item_cap_sys_chroot,	{ "sys chroot", "kdbus.item.cap.sys_chroot",				FT_BOOLEAN, 32, NULL, 1 << 18, NULL, HFILL }},
	{ &hf_kdbus_item_cap_sys_ptrace,	{ "sys ptrace", "kdbus.item.cap.sys_ptrace",				FT_BOOLEAN, 32, NULL, 1 << 19, NULL, HFILL }},
	{ &hf_kdbus_item_cap_sys_pacct,		{ "sys pacct", "kdbus.item.cap.sys_pacct",				FT_BOOLEAN, 32, NULL, 1 << 20, NULL, HFILL }},
	{ &hf_kdbus_item_cap_sys_admin,		{ "sys admin", "kdbus.item.cap.sys_admin",				FT_BOOLEAN, 32, NULL, 1 << 21, NULL, HFILL }},
	{ &hf_kdbus_item_cap_sys_boot,		{ "sys boot", "kdbus.item.cap.sys_boot",				FT_BOOLEAN, 32, NULL, 1 << 22, NULL, HFILL }},
	{ &hf_kdbus_item_cap_sys_nice,		{ "sys nice", "kdbus.item.cap.sys_nice",				FT_BOOLEAN, 32, NULL, 1 << 23, NULL, HFILL }},
	{ &hf_kdbus_item_cap_sys_resource,	{ "sys resource", "kdbus.item.cap.sys_resource",			FT_BOOLEAN, 32, NULL, 1 << 24, NULL, HFILL }},
	{ &hf_kdbus_item_cap_sys_time,		{ "sys time", "kdbus.item.cap.sys_time",				FT_BOOLEAN, 32, NULL, 1 << 25, NULL, HFILL }},
	{ &hf_kdbus_item_cap_sys_tty_config,	{ "sys tty config", "kdbus.item.cap.sys_tty_config",			FT_BOOLEAN, 32, NULL, 1 << 26, NULL, HFILL }},
	{ &hf_kdbus_item_cap_mknod,		{ "sys mknod", "kdbus.item.cap.mknod",					FT_BOOLEAN, 32, NULL, 1 << 27, NULL, HFILL }},
	{ &hf_kdbus_item_cap_lease,		{ "lease", "kdbus.item.cap.lease",					FT_BOOLEAN, 32, NULL, 1 << 28, NULL, HFILL }},
	{ &hf_kdbus_item_cap_audit_write,	{ "audit write", "kdbus.item.cap.audit_write",				FT_BOOLEAN, 32, NULL, 1 << 29, NULL, HFILL }},
	{ &hf_kdbus_item_cap_audit_control,	{ "audit control", "kdbus.item.cap.audit_control",			FT_BOOLEAN, 32, NULL, 1 << 30, NULL, HFILL }},
	{ &hf_kdbus_item_cap_setfcap,		{ "setfcap", "kdbus.item.cap.setfcap",					FT_BOOLEAN, 32, NULL, 1 << 31, NULL, HFILL }},

	/* caps u32.1 */
	{ &hf_kdbus_item_cap_mac_override,	{ "MAC override", "kdbus.item.cap.mac_override",			FT_BOOLEAN, 32, NULL, 1 << 0, NULL, HFILL }},
	{ &hf_kdbus_item_cap_admin,		{ "admin", "kdbus.item.cap.admin",					FT_BOOLEAN, 32, NULL, 1 << 1, NULL, HFILL }},
	{ &hf_kdbus_item_cap_syslog,		{ "syslog", "kdbus.item.cap.syslog",					FT_BOOLEAN, 32, NULL, 1 << 2, NULL, HFILL }},
	{ &hf_kdbus_item_cap_wake_alarm,	{ "wake alarm", "kdbus.item.cap.wake_alarm",				FT_BOOLEAN, 32, NULL, 1 << 3, NULL, HFILL }},
	{ &hf_kdbus_item_cap_block_suspend,	{ "block suspend", "kdbus.item.cap.block_suspend",			FT_BOOLEAN, 32, NULL, 1 << 4, NULL, HFILL }},
};

static gint *ett[] = {
	&ett_kdbus,
	&ett_kdbus_item,
};


/* Family values. */
static const value_string family_vals[] = {
	{ 0,	NULL },
};

static void
dissect_item(tvbuff_t *msg_tvb, tvbuff_t *tvb, proto_tree *tree)
{
	struct kdbus_item *item;
	uint64_t size;

	tvb_memcpy(tvb, &size, 0, sizeof(size));
	item = (struct kdbus_item *) tvb_memdup(wmem_packet_scope(), tvb, 0, size);

	proto_tree_add_uint64(tree, hf_kdbus_item_size, tvb, offsetof(struct kdbus_item, size), sizeof(uint64_t), item->size);
	proto_tree_add_uint64(tree, hf_kdbus_item_type, tvb, offsetof(struct kdbus_item, type), sizeof(uint64_t), item->type);

	switch (item->type) {
	case _KDBUS_ITEM_NULL:
		break;
	case KDBUS_ITEM_PAYLOAD_VEC:
		proto_tree_add_uint64(tree, hf_kdbus_item_vec_size,	tvb, offsetof(struct kdbus_item, vec.size),	sizeof(uint64_t), item->vec.size);
		proto_tree_add_uint64(tree, hf_kdbus_item_vec_address,	tvb, offsetof(struct kdbus_item, vec.address),	sizeof(uint64_t), item->vec.address);
		break;
	case KDBUS_ITEM_PAYLOAD_OFF:
		proto_tree_add_uint64(tree, hf_kdbus_item_vec_size,	tvb, offsetof(struct kdbus_item, vec.size),	sizeof(uint64_t), item->vec.size);
		proto_tree_add_uint64(tree, hf_kdbus_item_vec_offset,	tvb, offsetof(struct kdbus_item, vec.offset),	sizeof(uint64_t), item->vec.offset);

		if (item->vec.offset != ~0ULL)
			proto_tree_add_bytes(tree, hf_kdbus_item_vec_payload, msg_tvb, item->vec.offset, item->vec.size,
					     tvb_get_ptr(msg_tvb, item->vec.offset, item->vec.size));
		break;
	case KDBUS_ITEM_PAYLOAD_MEMFD:
		proto_tree_add_uint64(tree, hf_kdbus_item_memfd_size, tvb, offsetof(struct kdbus_item, memfd.size),	sizeof(uint64_t),	item->memfd.size);
		proto_tree_add_uint(tree, hf_kdbus_item_memfd_fd, tvb, offsetof(struct kdbus_item, memfd.fd),		sizeof(int),		item->memfd.fd);
		break;
	case KDBUS_ITEM_FDS: {
#if 0
		unsigned int i, len;

		len = (size - offsetof(struct kdbus_item, fd)) / sizeof(int);

		for (i = 0; i < len; i++)
			proto_tree_add_uint(tree, hf_kdbus_item_auxgroup_id, tvb, offsetof(struct kdbus_item, data64) + (i * sizeof(uint64_t)), sizeof(uint64_t), item->data64[i]);
#endif
		break;
	}
	case KDBUS_ITEM_NAME: {
		int flags_off = offsetof(struct kdbus_item, name) + offsetof(struct kdbus_name, flags);

		proto_tree_add_uint64(tree, hf_kdbus_msg_flags,			tvb, flags_off, sizeof(item->name.flags), item->name.flags);
		proto_tree_add_item(tree, hf_kdbus_name_flag_replace_existing,	tvb, flags_off, sizeof(uint64_t), ENC_HOST_ENDIAN);
		proto_tree_add_item(tree, hf_kdbus_name_flag_allow_replacement,	tvb, flags_off, sizeof(uint64_t), ENC_HOST_ENDIAN);
		proto_tree_add_item(tree, hf_kdbus_name_flag_queue,		tvb, flags_off, sizeof(uint64_t), ENC_HOST_ENDIAN);
		proto_tree_add_item(tree, hf_kdbus_name_flag_in_queue,		tvb, flags_off, sizeof(uint64_t), ENC_HOST_ENDIAN);
		proto_tree_add_item(tree, hf_kdbus_name_flag_activator,		tvb, flags_off, sizeof(uint64_t), ENC_HOST_ENDIAN);

		proto_tree_add_string(tree, hf_kdbus_item_string, tvb, offsetof(struct kdbus_item, name) + offsetof(struct kdbus_name, name),
				      size - offsetof(struct kdbus_item, name) - offsetof(struct kdbus_name, name),
				      item->name.name);
		break;
	}

	case KDBUS_ITEM_TIMESTAMP:
		proto_tree_add_uint64(tree, hf_kdbus_item_timestamp_seqnum,	tvb, offsetof(struct kdbus_item, timestamp.seqnum),		sizeof(uint64_t), item->timestamp.seqnum);
		proto_tree_add_uint64(tree, hf_kdbus_item_timestamp_monotonic,	tvb, offsetof(struct kdbus_item, timestamp.monotonic_ns),	sizeof(uint64_t), item->timestamp.monotonic_ns);
		proto_tree_add_uint64(tree, hf_kdbus_item_timestamp_realtime,	tvb, offsetof(struct kdbus_item, timestamp.realtime_ns),	sizeof(uint64_t), item->timestamp.realtime_ns);
		break;
	case KDBUS_ITEM_PIDS:
		proto_tree_add_uint64(tree, hf_kdbus_item_pids_pid,		tvb, offsetof(struct kdbus_item, pids.pid),	sizeof(uint64_t), item->pids.pid);
		proto_tree_add_uint64(tree, hf_kdbus_item_pids_tid,		tvb, offsetof(struct kdbus_item, pids.tid),	sizeof(uint64_t), item->pids.tid);
		proto_tree_add_uint64(tree, hf_kdbus_item_pids_ppid,		tvb, offsetof(struct kdbus_item, pids.ppid),	sizeof(uint64_t), item->pids.ppid);
		break;
	case KDBUS_ITEM_CREDS:
		proto_tree_add_uint64(tree, hf_kdbus_item_creds_uid,		tvb, offsetof(struct kdbus_item, creds.uid),	sizeof(uint64_t), item->creds.uid);
		proto_tree_add_uint64(tree, hf_kdbus_item_creds_euid,		tvb, offsetof(struct kdbus_item, creds.euid),	sizeof(uint64_t), item->creds.euid);
		proto_tree_add_uint64(tree, hf_kdbus_item_creds_suid,		tvb, offsetof(struct kdbus_item, creds.suid),	sizeof(uint64_t), item->creds.suid);
		proto_tree_add_uint64(tree, hf_kdbus_item_creds_fsuid,		tvb, offsetof(struct kdbus_item, creds.fsuid),	sizeof(uint64_t), item->creds.fsuid);
		proto_tree_add_uint64(tree, hf_kdbus_item_creds_gid,		tvb, offsetof(struct kdbus_item, creds.gid),	sizeof(uint64_t), item->creds.gid);
		proto_tree_add_uint64(tree, hf_kdbus_item_creds_egid,		tvb, offsetof(struct kdbus_item, creds.egid),	sizeof(uint64_t), item->creds.egid);
		proto_tree_add_uint64(tree, hf_kdbus_item_creds_sgid,		tvb, offsetof(struct kdbus_item, creds.sgid),	sizeof(uint64_t), item->creds.sgid);
		proto_tree_add_uint64(tree, hf_kdbus_item_creds_fsgid,		tvb, offsetof(struct kdbus_item, creds.fsgid),	sizeof(uint64_t), item->creds.fsgid);
		break;
	case KDBUS_ITEM_AUXGROUPS: {
		unsigned int i, len;

		len = (size - offsetof(struct kdbus_item, data64)) / sizeof(uint64_t);

		for (i = 0; i < len; i++)
			proto_tree_add_uint64(tree, hf_kdbus_item_auxgroup_id, tvb, offsetof(struct kdbus_item, data64) + (i * sizeof(uint64_t)), sizeof(uint64_t), item->data64[i]);
		break;
	}
	case KDBUS_ITEM_AUDIT:
		proto_tree_add_uint64(tree, hf_kdbus_item_audit_sessionid,	tvb, offsetof(struct kdbus_item, audit.sessionid),	sizeof(uint64_t), item->audit.sessionid);
		proto_tree_add_uint64(tree, hf_kdbus_item_audit_loginuid,	tvb, offsetof(struct kdbus_item, audit.loginuid),	sizeof(uint64_t), item->audit.loginuid);
		break;
	case KDBUS_ITEM_CAPS: {
		unsigned int i;
		int hfindex[] = {
			hf_kdbus_item_caps_inheritable,
			hf_kdbus_item_caps_permitted,
			hf_kdbus_item_caps_effective,
			hf_kdbus_item_caps_bset,
		};

		for (i = 0; i < G_N_ELEMENTS(hfindex); i++)
			proto_tree_add_bytes(tree, hfindex[i], tvb, offsetof(struct kdbus_item, data) + (KDBUS_CAP_SIZE * i), KDBUS_CAP_SIZE, item->data + (KDBUS_CAP_SIZE * i));
		break;
	}
	case KDBUS_ITEM_DST_NAME:
	case KDBUS_ITEM_PID_COMM:
	case KDBUS_ITEM_TID_COMM:
	case KDBUS_ITEM_EXE:
	case KDBUS_ITEM_CMDLINE:
	case KDBUS_ITEM_CGROUP:
	case KDBUS_ITEM_SECLABEL:
	case KDBUS_ITEM_CONN_DESCRIPTION:
		proto_tree_add_string(tree, hf_kdbus_item_string, tvb, offsetof(struct kdbus_item, str), size - offsetof(struct kdbus_item, str), item->str);
		break;
	case KDBUS_ITEM_ID_ADD:
		proto_tree_add_uint64(tree, hf_kdbus_item_conn_add_id,		tvb, offsetof(struct kdbus_item, id_change.id),		sizeof(item->id_change.id),	item->id_change.id);
		proto_tree_add_uint64(tree, hf_kdbus_item_conn_add_flags,	tvb, offsetof(struct kdbus_item, id_change.flags),	sizeof(item->id_change.flags),	item->id_change.flags);
		break;
	case KDBUS_ITEM_ID_REMOVE:
		proto_tree_add_uint64(tree, hf_kdbus_item_conn_remove_id,	tvb, offsetof(struct kdbus_item, id_change.id),		sizeof(item->id_change.id),	item->id_change.id);
		proto_tree_add_uint64(tree, hf_kdbus_item_conn_remove_flags,	tvb, offsetof(struct kdbus_item, id_change.flags),	sizeof(item->id_change.flags),	item->id_change.flags);
		break;
	case KDBUS_ITEM_NAME_ADD:
	case KDBUS_ITEM_NAME_REMOVE:
	case KDBUS_ITEM_NAME_CHANGE:
		proto_tree_add_uint64(tree, hf_kdbus_item_name_change_id_old,	tvb, offsetof(struct kdbus_item, name_change.old_id.id),	sizeof(item->name_change.old_id.id),	item->name_change.old_id.id);
		proto_tree_add_uint64(tree, hf_kdbus_item_name_change_flags_old,tvb, offsetof(struct kdbus_item, name_change.old_id.flags),	sizeof(item->name_change.old_id.flags),	item->name_change.old_id.flags);
		proto_tree_add_uint64(tree, hf_kdbus_item_name_change_id_new,	tvb, offsetof(struct kdbus_item, name_change.new_id.id),	sizeof(item->name_change.new_id.id),	item->name_change.new_id.id);
		proto_tree_add_uint64(tree, hf_kdbus_item_name_change_flags_new,tvb, offsetof(struct kdbus_item, name_change.new_id.flags),	sizeof(item->name_change.new_id.flags),	item->name_change.new_id.flags);
		proto_tree_add_string(tree, hf_kdbus_item_string, tvb, offsetof(struct kdbus_item, name_change.name), size - offsetof(struct kdbus_item, name_change.name), item->name_change.name);
		break;
	case KDBUS_ITEM_REPLY_TIMEOUT:
		break;
	case KDBUS_ITEM_REPLY_DEAD:
		break;
	}
}

static void
dissect_kdbus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	const char *payload_type, *kernel_type = NULL;
	const char *dst_name = NULL;
	uint64_t offset, msg_size;
	wmem_strbuf_t *tmpbuf;
	struct kdbus_msg *msg;
	int item_count;
	char *tmp;

	msg = (struct kdbus_msg *) tvb_get_ptr(tvb, 0, tvb_reported_length(tvb));

	proto_tree_add_uint64(tree, hf_kdbus_msg_size,			tvb, offsetof(struct kdbus_msg, size),		sizeof(msg->size),	msg->size);
	proto_tree_add_int64(tree, hf_kdbus_msg_priority,		tvb, offsetof(struct kdbus_msg, priority),	sizeof(msg->priority),	msg->priority);
	proto_tree_add_uint64(tree, hf_kdbus_msg_flags,			tvb, offsetof(struct kdbus_msg, flags),		sizeof(msg->flags),	msg->flags);

	proto_tree_add_item(tree, hf_kdbus_msg_flag_expect_reply,	tvb, offsetof(struct kdbus_msg, flags),		sizeof(uint64_t), ENC_HOST_ENDIAN);
	proto_tree_add_item(tree, hf_kdbus_msg_flag_no_auto_start,	tvb, offsetof(struct kdbus_msg, flags),		sizeof(uint64_t), ENC_HOST_ENDIAN);
	proto_tree_add_item(tree, hf_kdbus_msg_flag_signal,		tvb, offsetof(struct kdbus_msg, flags),		sizeof(uint64_t), ENC_HOST_ENDIAN);

	proto_tree_add_uint64(tree, hf_kdbus_msg_src_id,		tvb, offsetof(struct kdbus_msg, src_id),	sizeof(msg->src_id),		msg->src_id);
	proto_tree_add_uint64(tree, hf_kdbus_msg_dst_id,		tvb, offsetof(struct kdbus_msg, dst_id),	sizeof(msg->dst_id),		msg->dst_id);
	proto_tree_add_uint64(tree, hf_kdbus_msg_payload_type,		tvb, offsetof(struct kdbus_msg, payload_type),	sizeof(msg->payload_type),	msg->payload_type);
	proto_tree_add_uint64(tree, hf_kdbus_msg_cookie,		tvb, offsetof(struct kdbus_msg, cookie),	sizeof(msg->cookie),		msg->cookie);

	if (msg->flags & KDBUS_MSG_EXPECT_REPLY)
		proto_tree_add_uint64(tree, hf_kdbus_msg_timeout_ns,	tvb, offsetof(struct kdbus_msg, timeout_ns),	sizeof(msg->timeout_ns),	msg->timeout_ns);
	else
		proto_tree_add_uint64(tree, hf_kdbus_msg_cookie_reply,	tvb, offsetof(struct kdbus_msg, cookie_reply),	sizeof(msg->cookie_reply),	msg->cookie_reply);

	offset = offsetof(struct kdbus_msg, items);
	msg_size = msg->size - offset;
	item_count = 0;

	while (msg_size > 0) {
		proto_tree *subtree;
		proto_item *item;
		tvbuff_t *subtvb;
		uint64_t size;
		const char *item_type;
		struct {
			uint64_t size;
			uint64_t type;
		} hdr;

		tvb_memcpy(tvb, &hdr, offset, sizeof(hdr));
		size = KDBUS_ALIGN8(hdr.size);
		subtvb = tvb_new_subset_length(tvb, offset, size);

		if (hdr.type == KDBUS_ITEM_DST_NAME)
			dst_name = wmem_strdup(wmem_file_scope(),
					       tvb_get_ptr(subtvb, offsetof(struct kdbus_item, str),
							   size - offsetof(struct kdbus_item, str)));

		item = proto_tree_add_item(tree, proto_kdbus_item, tvb, offset, size, ENC_HOST_ENDIAN);
		item_type =  val_to_str(hdr.type, (const value_string *) item_types, "Unknown (0x%zx)");

		proto_item_append_text(item, ", Type '%s'", item_type);
		subtree = proto_item_add_subtree(item, ett_kdbus_item);

		dissect_item(tvb, subtvb, subtree);

		if (hdr.type > _KDBUS_ITEM_KERNEL_BASE)
			kernel_type = item_type;

		offset += size;
		msg_size -= size;
		item_count++;
	}

	payload_type = val_to_str(msg->payload_type,
				  (const value_string *) payload_types,
				  "Unknown (0x%zx)");
	col_set_str(pinfo->cinfo, COL_PROTOCOL, payload_type);

	tmpbuf = wmem_strbuf_new(wmem_file_scope(), "");
	wmem_strbuf_append_printf(tmpbuf, "%d items", item_count);
	if (msg->flags & KDBUS_MSG_EXPECT_REPLY)
		wmem_strbuf_append_printf(tmpbuf, ", reply expected");
	if (msg->flags & KDBUS_MSG_SIGNAL)
		wmem_strbuf_append_printf(tmpbuf, ", signal");

	if (kernel_type)
		wmem_strbuf_append_printf(tmpbuf, ", %s",  kernel_type);

	col_set_str(pinfo->cinfo, COL_INFO, wmem_strbuf_get_str(tmpbuf));

	if (msg->src_id) {
		tmp = wmem_strdup_printf(wmem_file_scope(), ":1.%llu", (unsigned long long) msg->src_id);
		col_set_str(pinfo->cinfo, COL_RES_DL_SRC, tmp);
	} else {
		col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "(kernel)");
	}

	if (msg->dst_id == KDBUS_DST_ID_NAME) {
		if (dst_name)
			col_set_str(pinfo->cinfo, COL_RES_DL_DST, dst_name);
		else
			col_set_str(pinfo->cinfo, COL_RES_DL_DST, "MISSING KDBUS_ITEM_DST_NAME");
	} else if (msg->dst_id == KDBUS_DST_ID_BROADCAST) {
		col_set_str(pinfo->cinfo, COL_RES_DL_DST, "(broadcast)");
	} else {
		tmp = wmem_strdup_printf(wmem_file_scope(), ":1.%llu", (unsigned long long) msg->dst_id);
		col_set_str(pinfo->cinfo, COL_RES_DL_DST, tmp);
	}

	tmp = wmem_strdup_printf(wmem_file_scope(), "%d", item_count);
	col_set_str(pinfo->cinfo, COL_NUMBER, tmp);
}

void
proto_register_kdbus(void)
{
	proto_kdbus = proto_register_protocol("kdbus", "kdbus", "kdbus");
	proto_register_field_array(proto_kdbus, hf_msg, array_length(hf_msg));
	proto_register_subtree_array(ett, array_length(ett));

	/* subdissector code */
	kdbus_dissector_table =
		register_dissector_table("kdbus.item", "kdbus item type",
					 FT_UINT32, BASE_HEX);

	proto_kdbus_item = proto_register_protocol("kdbus message item", "item", "kdbus.item");
	proto_register_field_array(proto_kdbus_item, hf_item, array_length(hf_item));
}

void
proto_reg_handoff_kdbus(void)
{
	dissector_handle_t kdbus_handle;

	item_handle = find_dissector("kdbus.item");
	kdbus_handle = create_dissector_handle(dissect_kdbus, proto_kdbus);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_KDBUS, kdbus_handle);
}
