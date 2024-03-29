#!/usr/bin/python3
# Copyright 2014 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`generator` --- SCION topology generator
=============================================
"""
# Stdlib
import argparse
import base64
import configparser
import getpass
import logging
import math
import os
import random
import sys
from collections import defaultdict
from io import StringIO
from string import Template

# External packages
import yaml
from Crypto import Random
from external.ipaddress import ip_address, ip_interface, ip_network
from OpenSSL import crypto

# SCION
from lib.config import Config
from lib.crypto.asymcrypto import (
    generate_sign_keypair,
    generate_enc_keypair,
)
from lib.crypto.certificate import Certificate
from lib.crypto.certificate_chain import CertificateChain
from lib.crypto.trc import (
    OFFLINE_KEY_ALG_STRING,
    OFFLINE_KEY_STRING,
    ONLINE_KEY_ALG_STRING,
    ONLINE_KEY_STRING,
    TRC,
)
from lib.defines import (
    AS_CONF_FILE,
    AS_LIST_FILE,
    DEFAULT_MTU,
    GEN_PATH,
    IFIDS_FILE,
    NETWORKS_FILE,
    PATH_POLICY_FILE,
    SCION_MIN_MTU,
    SCION_ROUTER_PORT,
    TOPO_FILE,
)
from lib.path_store import PathPolicy
from lib.packet.scion_addr import ISD_AS
from lib.topology import Topology
from lib.types import LinkType
from lib.util import (
    copy_file,
    get_ca_cert_file_path,
    get_ca_private_key_file_path,
    get_cert_chain_file_path,
    get_sig_key_file_path,
    get_enc_key_file_path,
    get_offline_key_file_path,
    get_online_key_file_path,
    get_trc_file_path,
    load_yaml_file,
    read_file,
    write_file,
)

DEFAULT_TOPOLOGY_FILE = "topology/Default.topo"
DEFAULT_PATH_POLICY_FILE = "topology/PathPolicy.yml"
DEFAULT_ZK_CONFIG = "topology/Zookeeper.yml"
DEFAULT_ZK_LOG4J = "topology/Zookeeper.log4j"

HOSTS_FILE = 'hosts'
SUPERVISOR_CONF = 'supervisord.conf'
COMMON_DIR = 'endhost'

ZOOKEEPER_HOST_TMPFS_DIR = "/run/shm/host-zk"
ZOOKEEPER_TMPFS_DIR = "/run/shm/scion-zk"

DEFAULT_LINK_BW = 1000

DEFAULT_BEACON_SERVERS = 1
DEFAULT_CERTIFICATE_SERVERS = 1
DEFAULT_PATH_SERVERS = 1
DEFAULT_SIBRA_SERVERS = 1
INITIAL_CERT_VERSION = 0
INITIAL_TRC_VERSION = 0

DEFAULT_NETWORK = "127.0.0.0/8"
DEFAULT_MININET_NETWORK = "100.64.0.0/10"
DEFAULT_ROUTER = "go"

SCION_SERVICE_NAMES = (
    "BeaconServers",
    "CertificateServers",
    "BorderRouters",
    "PathServers",
    "SibraServers",
)

DEFAULT_KEYGEN_ALG = 'Ed25519'


class ConfigGenerator(object):
    """
    Configuration and/or topology generator.
    """
    def __init__(self, out_dir=GEN_PATH, topo_file=DEFAULT_TOPOLOGY_FILE,
                 path_policy_file=DEFAULT_PATH_POLICY_FILE,
                 zk_config_file=DEFAULT_ZK_CONFIG, network=None,
                 use_mininet=False, router="py"):
        """
        Initialize an instance of the class ConfigGenerator.

        :param string out_dir: path to the topology folder.
        :param string topo_file: path to topology config
        :param string path_policy_file: path to PathPolicy.yml
        :param string zk_config_file: path to Zookeeper.yml
        :param string network:
            Network to create subnets in, of the form x.x.x.x/y
        :param bool use_mininet: Use Mininet
        """
        self.out_dir = out_dir
        self.topo_config = load_yaml_file(topo_file)
        self.zk_config = load_yaml_file(zk_config_file)
        self.path_policy_file = path_policy_file
        self.mininet = use_mininet
        self.default_zookeepers = {}
        self.default_mtu = None
        self.router = router
        self._read_defaults(network)

    def _read_defaults(self, network):
        """
        Configure default network and ZooKeeper setup.
        """
        defaults = self.topo_config.get("defaults", {})
        def_network = network
        if not def_network:
            def_network = defaults.get("subnet")
        if not def_network:
            if self.mininet:
                def_network = DEFAULT_MININET_NETWORK
            else:
                def_network = DEFAULT_NETWORK
        self.subnet_gen = SubnetGenerator(def_network)
        for key, val in defaults.get("zookeepers", {}).items():
            if self.mininet and val['addr'] == "127.0.0.1":
                val['addr'] = "169.254.0.1"
            self.default_zookeepers[key] = ZKTopo(
                val, self.zk_config)
        self.default_mtu = defaults.get("mtu", DEFAULT_MTU)

    def generate_all(self):
        """
        Generate all needed files.
        """
        ca_private_key_files, ca_cert_files, ca_certs = self._generate_cas()
        cert_files, trc_files = self._generate_certs_trcs(ca_certs)
        topo_dicts, zookeepers, networks = self._generate_topology()
        self._generate_supervisor(topo_dicts, zookeepers)
        self._generate_zk_conf(zookeepers)
        self._write_ca_files(topo_dicts, ca_private_key_files)
        self._write_ca_files(topo_dicts, ca_cert_files)
        self._write_trust_files(topo_dicts, cert_files)
        self._write_trust_files(topo_dicts, trc_files)
        self._write_conf_policies(topo_dicts)
        self._write_networks_conf(networks)

    def _generate_cas(self):
        ca_gen = CA_Generator(self.topo_config)
        return ca_gen.generate()

    def _generate_certs_trcs(self, ca_certs):
        certgen = CertGenerator(self.topo_config, ca_certs)
        return certgen.generate()

    def _generate_topology(self):
        topo_gen = TopoGenerator(
            self.topo_config, self.out_dir, self.subnet_gen, self.zk_config,
            self.default_mtu)
        return topo_gen.generate()

    def _generate_supervisor(self, topo_dicts, zookeepers):
        super_gen = SupervisorGenerator(
            self.out_dir, topo_dicts, zookeepers, self.zk_config, self.mininet,
            self.router)
        super_gen.generate()

    def _generate_zk_conf(self, zookeepers):
        zk_gen = ZKConfGenerator(self.out_dir, zookeepers)
        zk_gen.generate()

    def _write_ca_files(self, topo_dicts, ca_files):
        isds = set()
        for topo_id, as_topo in topo_dicts.items():
            isds.add(topo_id[0])
        for isd in isds:
            base = os.path.join(self.out_dir, "CAS")
            for path, value in ca_files[int(isd)].items():
                write_file(os.path.join(base, path), value.decode())

    def _write_trust_files(self, topo_dicts, cert_files):
        for topo_id, as_topo, base in _srv_iter(
                topo_dicts, self.out_dir, common=True):
            for path, value in cert_files[topo_id].items():
                write_file(os.path.join(base, path), value)

    def _write_conf_policies(self, topo_dicts):
        """
        Write AS configurations and path policies.
        """
        as_confs = {}
        for topo_id, as_topo, base in _srv_iter(
                topo_dicts, self.out_dir, common=True):
            as_confs.setdefault(topo_id, yaml.dump(
                self._gen_as_conf(as_topo), default_flow_style=False))
            conf_file = os.path.join(base, AS_CONF_FILE)
            write_file(conf_file, as_confs[topo_id])
            # Confirm that config parses cleanly.
            Config.from_file(conf_file)
            copy_file(self.path_policy_file,
                      os.path.join(base, PATH_POLICY_FILE))
        # Confirm that parser actually works on path policy file
        PathPolicy.from_file(self.path_policy_file)

    def _gen_as_conf(self, as_topo):
        master_as_key = base64.b64encode(Random.new().read(16))
        return {
            'MasterASKey': master_as_key.decode("utf-8"),
            'RegisterTime': 5,
            'PropagateTime': 5,
            'CertChainVersion': 0,
            # FIXME(kormat): This seems to always be true..:
            'RegisterPath': True if as_topo["PathServers"] else False,
        }

    def _write_networks_conf(self, networks):
        config = configparser.ConfigParser(interpolation=None)
        for i, net in enumerate(networks):
            sub_conf = {}
            for prog, ip_net in networks[net].items():
                sub_conf[prog] = ip_net.ip
            config[net] = sub_conf
        text = StringIO()
        config.write(text)
        write_file(os.path.join(self.out_dir, NETWORKS_FILE), text.getvalue())


class CertGenerator(object):
    def __init__(self, topo_config, ca_certs):
        self.topo_config = topo_config
        self.ca_certs = ca_certs
        self.sig_priv_keys = {}
        self.sig_pub_keys = {}
        self.enc_priv_keys = {}
        self.enc_pub_keys = {}
        self.pub_online_root_keys = {}
        self.priv_online_root_keys = {}
        self.pub_offline_root_keys = {}
        self.priv_offline_root_keys = {}
        self.certs = {}
        self.trcs = {}
        self.cert_files = defaultdict(dict)
        self.trc_files = defaultdict(dict)

    def generate(self):
        self._self_sign_keys()
        self._iterate(self._gen_as_keys)
        self._iterate(self._gen_as_certs)
        self._build_chains()
        self._iterate(self._gen_trc_entry)
        self._iterate(self._sign_trc)
        self._iterate(self._gen_trc_files)
        return self.cert_files, self.trc_files

    def _self_sign_keys(self):
        topo_id = TopoID.from_values(0, 0)
        self.sig_pub_keys[topo_id], self.sig_priv_keys[topo_id] = \
            generate_sign_keypair()
        self.enc_pub_keys[topo_id], self.enc_priv_keys[topo_id] = \
            generate_enc_keypair()

    def _iterate(self, f):
        for isd_as, as_conf in self.topo_config["ASes"].items():
            f(TopoID(isd_as), as_conf)

    def _gen_as_keys(self, topo_id, as_conf):
        sig_pub, sig_priv = generate_sign_keypair()
        enc_pub, enc_priv = generate_enc_keypair()
        self.sig_priv_keys[topo_id] = sig_priv
        self.sig_pub_keys[topo_id] = sig_pub
        self.enc_pub_keys[topo_id] = enc_pub
        self.enc_priv_keys[topo_id] = enc_priv
        sig_path = get_sig_key_file_path("")
        enc_path = get_enc_key_file_path("")
        self.cert_files[topo_id][sig_path] = base64.b64encode(sig_priv).decode()
        self.cert_files[topo_id][enc_path] = base64.b64encode(enc_priv).decode()
        if self.is_core(as_conf):
            # generate_sign_key_pair uses Ed25519
            on_root_pub, on_root_priv = generate_sign_keypair()
            off_root_pub, off_root_priv = generate_sign_keypair()
            self.pub_online_root_keys[topo_id] = on_root_pub
            self.priv_online_root_keys[topo_id] = on_root_priv
            self.pub_offline_root_keys[topo_id] = off_root_pub
            self.priv_offline_root_keys[topo_id] = off_root_priv
            online_key_path = get_online_key_file_path("")
            offline_key_path = get_offline_key_file_path("")
            self.cert_files[topo_id][online_key_path] = \
                base64.b64encode(on_root_priv).decode()
            self.cert_files[topo_id][offline_key_path] = \
                base64.b64encode(off_root_priv).decode()

    def _gen_as_certs(self, topo_id, as_conf):
        # Self-signed if cert_issuer is missing.
        issuer = TopoID(as_conf.get('cert_issuer', str(topo_id)))
        if self.is_core(as_conf):
            signing_key = self.priv_online_root_keys[topo_id]
        else:
            signing_key = self.sig_priv_keys[issuer]
        self.certs[topo_id] = Certificate.from_values(
            str(topo_id),  str(issuer), INITIAL_CERT_VERSION, "", False,
            self.enc_pub_keys[topo_id], self.sig_pub_keys[topo_id],
            signing_key
        )

    def _build_chains(self):
        for topo_id, cert in self.certs.items():
            chain = [cert]
            issuer = TopoID(cert.issuer)
            while issuer in self.certs:
                cert = self.certs[issuer]
                if str(issuer) == cert.issuer:
                    chain.append(cert)
                    break
                chain.append(cert)
                issuer = TopoID(cert.issuer)
            cert_path = get_cert_chain_file_path(
                "", topo_id, INITIAL_CERT_VERSION)
            self.cert_files[topo_id][cert_path] = \
                CertificateChain(chain).to_json()

    def is_core(self, as_conf):
        return as_conf.get("core")

    def _gen_trc_entry(self, topo_id, as_conf):
        if not as_conf.get('core', False):
            return
        if topo_id[0] not in self.trcs:
            self._create_trc(topo_id[0])
        trc = self.trcs[topo_id[0]]
        # Add public root online/offline key to TRC
        core = {}
        core[ONLINE_KEY_ALG_STRING] = DEFAULT_KEYGEN_ALG
        core[ONLINE_KEY_STRING] = self.pub_online_root_keys[topo_id]
        core[OFFLINE_KEY_ALG_STRING] = DEFAULT_KEYGEN_ALG
        core[OFFLINE_KEY_STRING] = self.priv_online_root_keys[topo_id]
        trc.core_ases[str(topo_id)] = core
        ca_certs = {}
        for ca_name, ca_cert in self.ca_certs[topo_id[0]].items():
            ca_certs[ca_name] = \
                 crypto.dump_certificate(crypto.FILETYPE_ASN1, ca_cert)
        trc.root_cas = ca_certs

    def _create_trc(self, isd):
        self.trcs[isd] = TRC.from_values(
            isd, "ISD %s" % isd, 0, {}, {},
            {}, 2, 'dns_srv_addr', 2,
            3, 18000, True, {})

    def _sign_trc(self, topo_id, as_conf):
        if not as_conf.get('core', False):
            return
        trc = self.trcs[topo_id[0]]
        trc.sign(str(topo_id), self.priv_online_root_keys[topo_id])

    def _gen_trc_files(self, topo_id, _):
        for isd in self.trcs:
            trc_path = get_trc_file_path("", isd, INITIAL_TRC_VERSION)
            self.trc_files[topo_id][trc_path] = str(self.trcs[isd])


class CA_Generator(object):
    def __init__(self, topo_config):
        self.topo_config = topo_config
        self.ca_key_pairs = {}
        self.ca_certs = defaultdict(dict)
        self.ca_private_key_files = defaultdict(dict)
        self.ca_cert_files = defaultdict(dict)

    def generate(self):
        self._iterate(self._gen_ca_key)
        self._iterate(self._gen_ca)
        self._iterate(self._gen_private_key_files)
        self._iterate(self._gen_cert_files)
        return self.ca_private_key_files, self.ca_cert_files, self.ca_certs

    def _iterate(self, f):
        for ca_name, ca_config in self.topo_config["CAs"].items():
            f(ca_name, ca_config)

    def _gen_ca_key(self, ca_name, ca_config):
        self.ca_key_pairs[ca_name] = crypto.PKey()
        self.ca_key_pairs[ca_name].generate_key(crypto.TYPE_RSA, 2048)

    def _gen_ca(self, ca_name, ca_config):
        ca = crypto.X509()
        ca.set_version(3)
        ca.set_serial_number(1)
        ca.get_subject().C = ca_config["countryName"]
        ca.get_subject().ST = ca_config["stateOrProvinceName"]
        ca.get_subject().L = ca_config["localityName"]
        ca.get_subject().O = ca_config["organizationName"]
        ca.get_subject().OU = ca_config["organizationalUnitName"]
        ca.gmtime_adj_notBefore(0)
        ca.gmtime_adj_notAfter(5 * 365 * 24 * 60 * 60)
        ca.set_issuer(ca.get_subject())
        ca.set_pubkey(self.ca_key_pairs[ca_name])

        # From RFC5280: Conforming CAs MUST include keyUsage extension in
        # certificates that contain public keys that are used to validate
        # digital signatures on other public key certificates or CRLs.
        # To facilitate certification path construction, subjectKeyIdentifier
        # extension MUST appear in all conforming CA certificates, that is, all
        # certificates including the basic constraints extension where the
        # value of cA is TRUE.
        ca.add_extensions([
            # basicConstraints identifies whether subject of certificate is a CA
            # pathLen expresses the number of possible intermediate CA
            # certificates in a path built from an end-entity certificate up
            # to the CA certificate.
            crypto.X509Extension(
                b"basicConstraints", True, b"CA:TRUE, pathlen:1"),
            # The keyCertSign bit is asserted when the subject public key is
            # used for verifying signatures on public key certificates.
            crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
            # From RFC5280: The keyIdentifier is composed of the 160-bit SHA-1
            # hash of the value of the BIT STRING subjectPublicKey
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash",
                                 subject=ca),
        ])
        ca.sign(self.ca_key_pairs[ca_name], "sha256")
        self.ca_certs[ca_config["ISD"]][ca_name] = ca

    def _gen_private_key_files(self, ca_name, ca_config):
        isd = ca_config["ISD"]
        ca_private_key_path = \
            get_ca_private_key_file_path("ISD%s" % isd, ca_name)
        self.ca_private_key_files[isd][ca_private_key_path] = \
            crypto.dump_privatekey(crypto.FILETYPE_PEM,
                                   self.ca_key_pairs[ca_name])

    def _gen_cert_files(self, ca_name, ca_config):
        isd = ca_config["ISD"]
        ca_cert_path = get_ca_cert_file_path("ISD%s" % isd, ca_name)
        self.ca_cert_files[isd][ca_cert_path] = \
            crypto.dump_certificate(crypto.FILETYPE_PEM,
                                    self.ca_certs[ca_config["ISD"]][ca_name])


class TopoGenerator(object):
    def __init__(self, topo_config, out_dir, subnet_gen, zk_config,
                 default_mtu):
        self.topo_config = topo_config
        self.out_dir = out_dir
        self.subnet_gen = subnet_gen
        self.zk_config = zk_config
        self.default_mtu = default_mtu
        self.topo_dicts = {}
        self.hosts = []
        self.zookeepers = defaultdict(dict)
        self.virt_addrs = set()
        self.as_list = defaultdict(list)
        self.links = defaultdict(list)
        self.ifid_map = {}

    def _reg_addr(self, topo_id, elem_id):
        subnet = self.subnet_gen.register(topo_id)
        return subnet.register(elem_id)

    def _reg_link_addrs(self, local_br, remote_br):
        link_name = str(sorted((local_br, remote_br)))
        subnet = self.subnet_gen.register(link_name)
        return subnet.register(local_br), subnet.register(remote_br)

    def _iterate(self, f):
        for isd_as, as_conf in self.topo_config["ASes"].items():
            f(TopoID(isd_as), as_conf)

    def generate(self):
        self._read_links()
        self._iterate(self._generate_as_topo)
        self._iterate(self._generate_as_list)
        networks = self.subnet_gen.alloc_subnets()
        self._write_as_topos()
        self._write_as_list()
        self._write_ifids()
        return self.topo_dicts, self.zookeepers, networks

    def _read_links(self):
        br_ids = defaultdict(int)
        if_ids = defaultdict(lambda: IFIDGenerator())
        for attrs in self.topo_config["links"]:
            # Pop the basic attributes, then append the remainder to the link
            # entry.
            a = TopoID(attrs.pop("a"))
            b = TopoID(attrs.pop("b"))
            ltype = ltype_a = ltype_b = attrs.pop("ltype")
            if ltype == LinkType.PARENT:
                ltype_a = LinkType.CHILD
                ltype_b = LinkType.PARENT
            br_ids[a] += 1
            a_br = "br%s-%d" % (a, br_ids[a])
            a_ifid = if_ids[a].new()
            br_ids[b] += 1
            b_br = "br%s-%d" % (b, br_ids[b])
            b_ifid = if_ids[b].new()
            self.links[a].append((ltype_a, b, attrs, a_br, b_br, a_ifid))
            self.links[b].append((ltype_b, a, attrs, b_br, a_br, b_ifid))
            a_desc = "%s %s" % (a_br, a_ifid)
            b_desc = "%s %s" % (b_br, b_ifid)
            self.ifid_map.setdefault(str(a), {})
            self.ifid_map[str(a)][a_desc] = b_desc
            self.ifid_map.setdefault(str(b), {})
            self.ifid_map[str(b)][b_desc] = a_desc

    def _generate_as_topo(self, topo_id, as_conf):
        mtu = as_conf.get('mtu', self.default_mtu)
        assert mtu >= SCION_MIN_MTU, mtu
        self.topo_dicts[topo_id] = {
            'Core': as_conf.get('core', False), 'ISD_AS': str(topo_id),
            'Zookeepers': {}, 'MTU': mtu,
        }
        for i in SCION_SERVICE_NAMES:
            self.topo_dicts[topo_id][i] = {}
        self._gen_srv_entries(topo_id, as_conf)
        self._gen_br_entries(topo_id)
        self._gen_zk_entries(topo_id, as_conf)

    def _gen_srv_entries(self, topo_id, as_conf):
        for conf_key, def_num, nick, topo_key in (
            ("beacon_servers", DEFAULT_BEACON_SERVERS, "bs", "BeaconServers"),
            ("certificate_servers", DEFAULT_CERTIFICATE_SERVERS, "cs",
             "CertificateServers"),
            ("path_servers", DEFAULT_PATH_SERVERS, "ps", "PathServers"),
            ("sibra_servers", DEFAULT_SIBRA_SERVERS, "sb", "SibraServers"),
        ):
            self._gen_srv_entry(
                topo_id, as_conf, conf_key, def_num, nick, topo_key)

    def _gen_srv_entry(self, topo_id, as_conf, conf_key, def_num, nick,
                       topo_key):
        count = as_conf.get(conf_key, def_num)
        for i in range(1, count + 1):
            elem_id = "%s%s-%s" % (nick, topo_id, i)
            d = {}
            d["Addr"] = self._reg_addr(topo_id, elem_id)
            d["Port"] = random.randint(30050, 30100)
            self.topo_dicts[topo_id][topo_key][elem_id] = d

    def _gen_br_entries(self, topo_id):
        for (ltype, remote, attrs, local_br,
             remote_br, ifid) in self.links[topo_id]:
            self._gen_br_entry(topo_id, ifid, remote, ltype, attrs, local_br,
                               remote_br)

    def _gen_br_entry(self, local, ifid, remote, remote_type, attrs, local_br,
                      remote_br):
        public_addr, remote_addr = self._reg_link_addrs(
            local_br, remote_br)
        self.topo_dicts[local]["BorderRouters"][local_br] = {
            'Addr': self._reg_addr(local, local_br),
            'Port': random.randint(30050, 30100),
            'Interface': {
                'IFID': ifid,
                'ISD_AS': str(remote),
                'LinkType': remote_type,
                'Addr': public_addr,
                'ToAddr': remote_addr,
                'UdpPort': SCION_ROUTER_PORT,
                'ToUdpPort': SCION_ROUTER_PORT,
                'Bandwidth': attrs.get('bw', DEFAULT_LINK_BW),
                'MTU': attrs.get('mtu', DEFAULT_MTU),
            }
        }

    def _gen_zk_entries(self, topo_id, as_conf):
        zk_conf = {}
        if "zookeepers" in as_conf:
            zk_conf = as_conf["zookeepers"]
        elif "zookeepers" in self.topo_config.get("defaults", {}):
            zk_conf = self.topo_config["defaults"]["zookeepers"]
        for key, val in zk_conf.items():
            self._gen_zk_entry(topo_id, key, val)

    def _gen_zk_entry(self, topo_id, zk_id, zk_conf):
        zk = ZKTopo(zk_conf, self.zk_config)
        if zk.manage:
            elem_id = "zk%s-%s" % (topo_id, zk_id)
            addr = zk.addr = self._reg_addr(topo_id, elem_id)
            self.zookeepers[topo_id][elem_id] = zk_id, zk
        else:
            addr = str(zk.addr)
        self.topo_dicts[topo_id]["Zookeepers"][zk_id] = {
            'Addr': addr,
            'Port': zk.clientPort,
        }

    def _generate_as_list(self, topo_id, as_conf):
        if as_conf.get('core', False):
            key = "Core"
        else:
            key = "Non-core"
        self.as_list[key].append(str(topo_id))

    def _write_as_topos(self):
        for topo_id, as_topo, base in _srv_iter(
                self.topo_dicts, self.out_dir, common=True):
            path = os.path.join(base, TOPO_FILE)
            contents = yaml.dump(self.topo_dicts[topo_id],
                                 default_flow_style=False)
            write_file(path, contents)
            # Test if topo file parses cleanly
            Topology.from_file(path)

    def _write_as_list(self):
        list_path = os.path.join(self.out_dir, AS_LIST_FILE)
        write_file(list_path, yaml.dump(dict(self.as_list)))

    def _write_ifids(self):
        list_path = os.path.join(self.out_dir, IFIDS_FILE)
        write_file(list_path, yaml.dump(self.ifid_map,
                                        default_flow_style=False))


class SupervisorGenerator(object):
    def __init__(self, out_dir, topo_dicts, zookeepers, zk_config, mininet,
                 router):
        self.out_dir = out_dir
        self.topo_dicts = topo_dicts
        self.zookeepers = zookeepers
        self.zk_config = zk_config
        self.mininet = mininet
        self.router = router

    def generate(self):
        self._write_dispatcher_conf()
        for topo_id, topo in self.topo_dicts.items():
            self._as_conf(topo_id, topo)

    def _as_conf(self, topo_id, topo):
        entries = []
        base = self._get_base_path(topo_id)
        for key, cmd in (
            ("BeaconServers", "bin/beacon_server"),
            ("CertificateServers", "bin/cert_server"),
            ("PathServers", "bin/path_server"),
            ("SibraServers", "bin/sibra_server"),
        ):
            entries.extend(self._std_entries(topo, key, cmd, base))
        if self.router == "go":
            entries.extend(self._br_entries(topo, "bin/border", base))
        else:
            entries.extend(self._std_entries(topo, "BorderRouters",
                                             "bin/router", base))
        entries.extend(self._zk_entries(topo_id))
        self._write_as_conf(topo_id, entries)

    def _std_entries(self, topo, topo_key, cmd, base):
        entries = []
        for elem in topo.get(topo_key, {}):
            conf_dir = os.path.join(base, elem)
            entries.append((elem, [cmd, elem, conf_dir]))
        return entries

    def _br_entries(self, topo, cmd, base):
        entries = []
        for elem in topo.get("BorderRouters", {}):
            conf_dir = os.path.join(base, elem)
            entries.append((elem, [cmd, "-id", elem, "-confd", conf_dir]))
        return entries

    def _zk_entries(self, topo_id):
        if topo_id not in self.zookeepers:
            return []
        entries = []
        for name, (_, zk) in self.zookeepers[topo_id].items():
            entries.append((name, zk.super_conf(topo_id, name, self.out_dir)))
        return entries

    def _write_as_conf(self, topo_id, entries):
        config = configparser.ConfigParser(interpolation=None)
        names = []
        base = os.path.join(self.out_dir, topo_id.ISD(), topo_id.AS())
        for elem, entry in sorted(entries, key=lambda x: x[0]):
            names.append(elem)
            elem_dir = os.path.join(base, elem)
            self._write_elem_conf(elem, entry, elem_dir)
            if self.mininet:
                self._write_elem_mininet_conf(elem, elem_dir)
        config["group:as%s" % topo_id] = {"programs": ",".join(names)}
        text = StringIO()
        config.write(text)
        conf_path = os.path.join(self.out_dir, topo_id.ISD(), topo_id.AS(),
                                 SUPERVISOR_CONF)
        write_file(conf_path, text.getvalue())

    def _write_elem_conf(self, elem, entry, elem_dir):
        config = configparser.ConfigParser(interpolation=None)
        prog = self._common_entry(elem, entry, elem_dir)
        self._write_zlog_cfg(os.path.basename(entry[0]), elem, elem_dir)
        if self.mininet and not elem.startswith("br"):
            prog['environment'] += ',DISPATCHER_ID="%s"' % elem
            dp_name = "dp-" + elem
            dp = self._common_entry(dp_name, ["bin/dispatcher"], elem_dir)
            dp['environment'] += ',DISPATCHER_ID="%s"' % elem
            config["program:%s" % dp_name] = dp
            self._write_zlog_cfg("dispatcher", dp_name, elem_dir)
        if elem.startswith("br") and self.router == "go":
            prog['environment'] += ',GODEBUG="cgocheck=0"'
        config["program:%s" % elem] = prog
        text = StringIO()
        config.write(text)
        write_file(os.path.join(elem_dir, SUPERVISOR_CONF), text.getvalue())

    def _write_elem_mininet_conf(self, elem, elem_dir):
        tmpl = Template(read_file("topology/mininet/supervisord.conf"))
        mn_conf_path = os.path.join(self.out_dir, "mininet", "%s.conf" % elem)
        rel_conf_path = os.path.relpath(
            os.path.join(elem_dir, SUPERVISOR_CONF),
            os.path.join(self.out_dir, "mininet")
        )
        write_file(mn_conf_path,
                   tmpl.substitute(elem=elem, conf_path=rel_conf_path,
                                   user=getpass.getuser()))

    def _write_zlog_cfg(self, name, elem, elem_dir):
        tmpl = Template(read_file("topology/zlog.tmpl"))
        cfg = os.path.join(elem_dir, "%s.zlog.conf" % elem)
        write_file(cfg, tmpl.substitute(name=name, elem=elem))

    def _write_dispatcher_conf(self):
        elem = "dispatcher"
        elem_dir = os.path.join(self.out_dir, elem)
        self._write_elem_conf(elem, ["bin/dispatcher"], elem_dir)

    def _get_base_path(self, topo_id):
        return os.path.join(self.out_dir, topo_id.ISD(), topo_id.AS())

    def _common_entry(self, name, cmd_args, elem_dir):
        zlog = os.path.join(elem_dir, "%s.zlog.conf" % name)
        entry = {
            'autostart': 'false' if self.mininet else 'false',
            'autorestart': 'false',
            'environment': 'PYTHONPATH=.,ZLOG_CFG="%s"' % zlog,
            'stdout_logfile': "NONE",
            'stderr_logfile': "NONE",
            'startretries': 0,
            'startsecs': 5,
            'priority': 100,
            'command': self._mk_cmd(name, cmd_args),
        }
        if name == "dispatcher":
            entry['startsecs'] = 1
            entry['priority'] = 50
        if self.mininet:
            entry['autostart'] = 'true'
        return entry

    def _mk_cmd(self, name, cmd_args):
        return "bash -c 'exec %s &>logs/%s.OUT'" % (
            " ".join(['"%s"' % arg for arg in cmd_args]), name)


class ZKConfGenerator(object):
    def __init__(self, out_dir, zookeepers):
        self.out_dir = out_dir
        self.zookeepers = zookeepers
        self.datalog_dirs = []

    def generate(self):
        for topo_id, zks in self.zookeepers.items():
            self._write_as_zk_configs(topo_id, zks)
        self._write_datalog_dirs()

    def _write_as_zk_configs(self, topo_id, zks):
        # Build up server block
        servers = []
        for id_, zk in zks.values():
            servers.append("server.%s=%s:%d:%d" %
                           (id_, zk.addr.ip, zk.leaderPort, zk.electionPort))
        server_block = "\n".join(sorted(servers))
        base_dir = os.path.join(self.out_dir, topo_id.ISD(), topo_id.AS())
        for name, (id_, zk) in zks.items():
            copy_file(DEFAULT_ZK_LOG4J,
                      os.path.join(base_dir, name, "log4j.properties"))
            text = StringIO()
            datalog_dir = os.path.join(ZOOKEEPER_TMPFS_DIR, name)
            text.write("%s\n\n" % zk.zk_conf(
                os.path.join(base_dir, name, "data"), datalog_dir,
            ))
            text.write("%s\n" % server_block)
            write_file(os.path.join(base_dir, name, 'zoo.cfg'), text.getvalue())
            write_file(os.path.join(base_dir, name, "data", "myid"),
                       "%s\n" % id_)
            self.datalog_dirs.append(datalog_dir)

    def _write_datalog_dirs(self):
        text = StringIO()
        text.write("#!/bin/bash\n\n")
        text.write(
            "if [ ! -e %(dir)s ]; then\n"
            "  echo 'Creating %(dir)s & restarting zookeeper'\n"
            "  sudo mkdir -p %(dir)s\n"
            "  sudo chown -R zookeeper: %(dir)s\n"
            "  sudo service zookeeper restart\n"
            "fi\n" % {"dir": ZOOKEEPER_HOST_TMPFS_DIR}
        )
        for d in self.datalog_dirs:
            text.write("mkdir -p %s\n" % d)
        write_file(os.path.join(self.out_dir, "zk_datalog_dirs.sh"),
                   text.getvalue())


class TopoID(ISD_AS):
    def ISD(self):
        return "ISD%s" % self._isd

    def AS(self):
        return "AS%s" % self._as

    def __lt__(self, other):
        return str(self) < str(other)

    def __repr__(self):
        return "<TopoID: %s>" % self


class ZKTopo(object):
    def __init__(self, topo_config, zk_config):
        self.addr = None
        self.topo_config = topo_config
        self.zk_config = zk_config
        self.manage = self.topo_config.get("manage", False)
        if not self.manage:
            # A ZK we don't manage must have an assigned IP in the topology
            self.addr = ip_address(self.topo_config["addr"])
        self.clientPort = self._get_def("clientPort")
        self.leaderPort = self._get_def("leaderPort")
        self.electionPort = self._get_def("electionPort")
        self.maxClientCnxns = self._get_def("maxClientCnxns")

    def _get_def(self, key):
        return self.topo_config.get(key, self.zk_config["Default"][key])

    def zk_conf(self, data_dir, data_log_dir):
        c = []
        for s in ('tickTime', 'initLimit', 'syncLimit', 'maxClientCnxns'):
            c.append("%s=%s" % (s, self._get_def(s)))
        c.append("dataDir=%s" % data_dir)
        c.append("dataLogDir=%s" % data_log_dir)
        c.append("clientPort=%s" % self.clientPort)
        c.append("clientPortAddress=%s" % self.addr.ip)
        c.append("autopurge.purgeInterval=1")
        return "\n".join(c)

    def super_conf(self, topo_id, name, out_dir):
        base_dir = os.path.join(out_dir, topo_id.ISD(), topo_id.AS(), name)
        cfg_path = os.path.join(base_dir, "zoo.cfg")
        class_path = ":".join([
            base_dir, self.zk_config["Environment"]["CLASSPATH"],
        ])
        return [
            "java", "-cp", class_path,
            '-Dzookeeper.log.file=logs/%s.log' % name,
            self.zk_config["Environment"]["ZOOMAIN"], cfg_path,
        ]


class SubnetGenerator(object):
    def __init__(self, network):
        self._net = ip_network(network)
        if "/" not in network:
            logging.critical("No prefix length specified for network '%s'",
                             network)
            sys.exit(1)
        self._subnets = defaultdict(lambda: AddressGenerator())
        self._allocations = defaultdict(list)
        # Initialise the allocations with the supplied network, making sure to
        # exclude 127.0.0.0/30 if it's contained in the network.
        # - 127.0.0.0 is treated as a broadcast address by the kernel
        # - 127.0.0.1 is the normal loopback address
        # - 127.0.0.[23] are used for clients to bind to for testing purposes.
        v4_lo = ip_network("127.0.0.0/30")
        if self._net.overlaps(v4_lo):
            self._exclude_net(self._net, v4_lo)
        else:
            self._allocations[self._net.prefixlen].append(self._net)

    def register(self, location):
        return self._subnets[location]

    def alloc_subnets(self):
        max_prefix = self._net.max_prefixlen
        networks = {}
        for topo, subnet in sorted(self._subnets.items(), key=lambda x: str(x)):
            # Figure out what size subnet we need. If it's a link, then we just
            # need a /31 (or /127), otherwise add 2 to the subnet size to cover
            # the network and broadcast addresses.
            if len(subnet) == 2:
                req_prefix = max_prefix - 1
            else:
                req_prefix = max_prefix - math.ceil(math.log2(len(subnet) + 2))
            # Search all subnets from that size upwards
            for prefix in range(req_prefix, -1, -1):
                if not self._allocations[prefix]:
                    # No subnets available at this size
                    continue
                alloc = self._allocations[prefix].pop()
                # Carve out subnet of the required size
                new_net = next(alloc.subnets(new_prefix=req_prefix))
                logging.debug("Allocating %s from %s for subnet size %d" %
                              (new_net, alloc, len(subnet)))
                networks[new_net] = subnet.alloc_addrs(new_net)
                # Repopulate the allocations list with the left-over space
                self._exclude_net(alloc, new_net)
                break
            else:
                logging.critical("Unable to allocate /%d subnet" % req_prefix)
                sys.exit(1)
        return networks

    def _exclude_net(self, alloc, net):
        for net in alloc.address_exclude(net):
            self._allocations[net.prefixlen].append(net)


class AddressGenerator(object):
    def __init__(self):
        self._addrs = defaultdict(lambda: AddressProxy())

    def register(self, id_):
        return self._addrs[id_]

    def alloc_addrs(self, subnet):
        hosts = subnet.hosts()
        interfaces = {}
        for elem, proxy in sorted(self._addrs.items()):
            intf = ip_interface("%s/%s" % (next(hosts), subnet.prefixlen))
            interfaces[elem] = intf
            proxy.set_intf(intf)
        return interfaces

    def __len__(self):
        return len(self._addrs)


class AddressProxy(yaml.YAMLObject):
    yaml_tag = ""

    def __init__(self):
        self._intf = None
        self.ip = None

    def set_intf(self, intf):
        self._intf = intf
        self.ip = self._intf.ip

    def __str__(self):
        return str(self._intf)

    @classmethod
    def to_yaml(cls, dumper, inst):
        return dumper.represent_scalar('tag:yaml.org,2002:str', str(inst.ip))


class IFIDGenerator(object):
    """Generates unique interface IDs"""
    def __init__(self):
        self._ifids = set()

    def new(self):
        while True:
            ifid = random.randrange(10, 100)
            if ifid in self._ifids:
                continue
            self._ifids.add(ifid)
            return ifid


def _srv_iter(topo_dicts, out_dir, common=False):
    for topo_id, as_topo in topo_dicts.items():
        base = os.path.join(out_dir, topo_id.ISD(), topo_id.AS())
        for service in SCION_SERVICE_NAMES:
            for elem in as_topo[service]:
                yield topo_id, as_topo, os.path.join(base, elem)
        if common:
            yield topo_id, as_topo, os.path.join(base, COMMON_DIR)


def main():
    """
    Main function.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--topo-config', default=DEFAULT_TOPOLOGY_FILE,
                        help='Default topology config')
    parser.add_argument('-p', '--path-policy', default=DEFAULT_PATH_POLICY_FILE,
                        help='Path policy file')
    parser.add_argument('-m', '--mininet', action='store_true',
                        help='Use Mininet to create a virtual network topology')
    parser.add_argument('-n', '--network',
                        help='Network to create subnets in (E.g. "127.0.0.0/8"')
    parser.add_argument('-o', '--output-dir', default=GEN_PATH,
                        help='Output directory')
    parser.add_argument('-z', '--zk-config', default=DEFAULT_ZK_CONFIG,
                        help='Zookeeper configuration file')
    parser.add_argument('-r', '--router', default=DEFAULT_ROUTER,
                        help='Router implementation to use ("go" or "py")')
    args = parser.parse_args()
    confgen = ConfigGenerator(
        args.output_dir, args.topo_config, args.path_policy, args.zk_config,
        args.network, args.mininet, args.router)
    confgen.generate_all()


if __name__ == "__main__":
    main()
