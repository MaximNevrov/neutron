# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 UnitedStack, Inc.
# All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# @author: Jianing Yang, UnitedStack, Inc

import netaddr
import re
import sqlalchemy as sa
from sqlalchemy import orm

from neutron.common import utils
from neutron.db import db_base_plugin_v2
from neutron.db import l3_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import l3
from neutron.extensions import portforwardings
from oslo_db import exception as db_exc
from oslo_log import log as logging
from neutron._i18n import _, _LE

LOG = logging.getLogger(__name__)


class PortForwarding(model_base.BASEV2, models_v2.Forwarding):
#    __tablename__ = "portforwardings"
    router_id = sa.Column(sa.String(36),sa.ForeignKey('routers.id',ondelete="CASCADE"),primary_key=True)
#
#    outside_port = sa.Column(sa.Integer(), nullable=False, primary_key=True)
#    inside_addr = sa.Column(sa.String(15), nullable=False, primary_key=True)
#    inside_port = sa.Column(sa.Integer(), nullable=False, primary_key=True)
#    protocol = sa.Column(sa.String(4), nullable=False, primary_key=True)

    router = orm.relationship(l3_db.Router,
                              backref=orm.backref("portforwarding_list",
                                                  lazy='joined',
                                                  cascade='delete'))

class PortForwardingDbOnlyMixin(l3_db.L3_NAT_dbonly_mixin):
    """Mixin class to support nat rule configuration on router."""

    def _extend_router_dict_portforwarding(self, router_res, router_db):
        LOG.error(_LE('router_res before convert %s'), router_res)
        LOG.error(_LE('router_db before convert %s'), router_db)
#        LOG.error(_LE('router_db.port_forwardings before convert %s'), router_db.port_forwardings)
#        LOG.error(_LE('router_db[\'port_forwardings\'] before convert %s'), router_db['port_forwardings'])
        router_res['portforwardings'] = PortForwardingDbOnlyMixin._make_portforwardings_dict(router_db["portforwarding_list"])
        LOG.error(_LE('router_res after convert %s'), router_res)
        LOG.error(_LE('router_db after convert %s'), router_db)

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        l3.ROUTERS, ['_extend_router_dict_portforwarding'])

    def update_router(self, context, id, router):
#        LOG.error(_LE('execute update_router func with router %s'), router)
        r = router['router']
        with context.session.begin(subtransactions=True):
            router_db = self._get_router(context, id)
            if 'portforwardings' in r:
                try:
                    self._validate_fwds(context, router_db,
                                        r['portforwardings'])
                    self._update_extra_portfwds(context, router_db,
                                                r['portforwardings'])
                    context.session.flush()
                except db_exc.DBDuplicateEntry as e:
                    if 'outside_port' in e.columns:
                        found = re.search("Duplicate entry '(\d+)' "
                                          "for key 'outside_port'",
                                          e.inner_exception.message)
                        if found:
                            raise portforwardings.DuplicatedOutsidePort(
                                port=found.group(1))
                        else:
                            raise portforwardings.DuplicatedOutsidePort(
                                port="unknown")
                    # NOTE(jianingy): raise original exception directly if
                    #                 duplication not caused by identical ports
                    raise
            portfwds = self._get_extra_portfwds_by_router_id(context, id)
#        LOG.error(_LE('portfwds var: %s'), portfwds)
        router_updated = super(PortForwardingDbOnlyMixin, self).update_router(
            context, id, router)
        router_updated['portforwardings'] = portfwds
#        LOG.error(_LE('router_db var: %s'), router)
        return router_updated

    def _validate_fwds(self, context, router, portfwds):
#        LOG.error(_LE('_validate_fwds function executed'))
        query = context.session.query(models_v2.Network).join(models_v2.Port)
        networks = query.filter_by(device_id=router['id'])
        subnets = []
        for network in networks:
            subnets.extend(map(lambda x: x['cidr'], network.subnets))

        ip_addr, ip_net = netaddr.IPAddress, netaddr.IPNetwork
        for portfwd in portfwds:
            ip_str = portfwd['inside_addr']
            valid = any([ip_addr(ip_str) in ip_net(x) for x in subnets])
            if not valid:
                raise portforwardings.InvalidInsideAddress(inside_addr=ip_str)

    def _update_extra_portfwds(self, context, router, portfwds):
        LOG.error(_LE('portfwds var from _update_extra_portfwds function: %s'), portfwds)
        LOG.error(_LE('router var from _update_extra_portfwds function: %s'), router)
        old_fwds = self._get_extra_portfwds_by_router_id(context, router['id'])
        LOG.error(_LE('old_fwds var from _update_extra_portfwds function: %s'), old_fwds)
        added, removed = utils.diff_list_of_dict(old_fwds, portfwds)
        LOG.debug(_('Removed port forwarding rules are %s'), removed)
        # note(jianingy): remove first so that we won't encounter duplicated
        #                 entry.
        for portfwd in removed:
            del_context = context.session.query(PortForwarding)
            del_context.filter_by(router_id=router['id'],
                                  outside_port=portfwd['outside_port'],
                                  inside_addr=portfwd['inside_addr'],
                                  inside_port=portfwd['inside_port'],
                                  protocol=portfwd['protocol']).delete()
        LOG.debug(_('Added port forwarding rules are %s'), added)
        for portfwd in added:
            router_fwds = PortForwarding(
                router_id=router['id'],
                outside_port=portfwd['outside_port'],
                inside_addr=portfwd['inside_addr'],
                inside_port=portfwd['inside_port'],
                protocol=portfwd['protocol'])

            context.session.add(router_fwds)

    def _get_extra_portfwds_by_router_id(self, context, id):
        query = context.session.query(PortForwarding)
        query = query.filter_by(router_id=id)
        LOG.error(_LE('query var from _get_extra_portfwds_by_router_id function: %s'), query)
        return self._make_portforwardings_dict(query)

    @staticmethod
    def _make_portforwardings_dict(portforwardings):
        return [{'outside_port': portfwd['outside_port'],
                 'inside_addr': portfwd['inside_addr'],
                 'inside_port': portfwd['inside_port'],
                 'protocol': portfwd['protocol']
                 }
                for portfwd in portforwardings]

class ExtraRoute_db_mixin(PortForwardingDbOnlyMixin, l3_db.L3_NAT_db_mixin):
    """Mixin class to support extra route configuration on router with rpc."""
    pass