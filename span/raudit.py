# Copyright 2025 Lupus Maximus LLC
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# This is code for getting audit messages from remote systems and using
# them within span.

from sh import sshpass
from sh import audit2allow as audit2allowcmd
from sh import ssh as sshcmd
import sepolgen.audit as audit
from pandas import DataFrame

def ssh(remote_host, password, cmd_string):
    if password is not None:
        return sshpass("sshpass", "-p", password, "ssh", remote_host, cmd_string)
    else:
        return sshcmd(remote_host, cmd_string)

def remote_sudo(remote_host, password, cmd_string):
    return ssh(remote_host, password, "sudo " + cmd_string)

def get_audit_messages(remote_host, password=None):
    return remote_sudo(remote_host, password, "cat /var/log/audit/audit.log")

def get_audit_msg(audit_id, remote_host, password=None):
    return remote_sudo(remote_host, password, "ausearch --input-logs -i -a " + audit_id)

type_to_name = {
    0: "ALLOW",
    -6: "BADCOMPUTE",
    -5: "BADPERM",
    -2: "BADSCON",
    -4: "BADTCLASS",
    -3: "BADTCON",
    3: "BOOLEAN",
    6: "BOUNDS",
    4: "CONSTRAINT",
    1: "DONTAUDIT",
    -7: "NOPOLICY",
    5: "RBAC",
    2: "TERULE",
    -1: "UNKNOWN",
}
def av_to_dict(av):
    return {
        "src_type": av.src_type,
        "tgt_type": av.tgt_type,
        "obj_class": av.obj_class,
        "perms": av.perms,
        "xperms": av.xperms,
        "type": type_to_name[av.type],
        "names": {x.name for x in av.audit_msgs if x != ""},
        "audit_msgs": [x.audit_id for x in av.audit_msgs][:5],
    }

def get_audit(remote_host, password=None):
    parser = audit.AuditParser()
    parser.parse_string(get_audit_messages(remote_host, password))
    avs = [av_to_dict(x) for x in parser.to_access()][1:]
    df = DataFrame(avs)
    return df

def audit2allow(remote_host, password, *args):
    msgs = get_audit_messages(remote_host, password)

    return audit2allowcmd(_in=msgs, *args)

