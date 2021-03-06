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
import six
import abc
from string import split
import webob.exc
from neutron._i18n import _
from oslo_log import log as logging
from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.common import exceptions as qexception
from neutron import manager
from neutron.quota import resource_registry
from neutron.api.v2 import base

LOG = logging.getLogger(__name__)

# Duplicated Outside Port Exceptions
class DuplicatedOutsidePort(qexception.InvalidInput):
    message = ("Outside port %(port)s has already been used.")


class AlreadyExist(qexception.InvalidInput):
    message = ("Port forwarding rule %(rule)s is already exist.")


class InvalidInsideAddress(qexception.InvalidInput):
    message = ("Inside address %(inside_addr)s does not match "
                "any subnets in this router. Error message: %(msg)s.")


class InvalidInsideAddress2(qexception.InvalidInput):
    message = ("Inside address %(inside_addr)s does not match "
                "any subnets in this router. Error message: %(msg)s.")


class InvalidPortValue(qexception.InvalidInput):
    message = _("Invalid value for port %(port)s. Error message: %(msg)s.")


class InvalidProtocol(qexception.InvalidInput):
    message = _("Port forwarding rule protocol %(protocol)s not supported.")


class InvalidInput(qexception.InvalidInput):
    message = _("Wrong input value %(portfwd)s. Error message: %(msg)s")


class DuplicatePortforwardingRuleInRequest(qexception.InvalidInput):
    message = _("Request contains duplicate port forwarding rules: %(portfwds)s")

"""def convert_validate_port_value(port):
    if port is None:
        return port
    try:
        val = int(port)
    except (ValueError, TypeError):
        raise InvalidPortValue(port=port, msg="Not integer")

    if val >= 0 and val <= 65535:
        return val
    else:
        raise InvalidPortValue(port=port, msg="Not in 0-65535 range")

def convert_validate_protocol(value):
    if value is None:
        return
    try:
        val = int(value)
        if val >= 0 and val <= 255:
            # Set value of protocol number to string due to bug 1381379,
            # PostgreSQL fails when it tries to compare integer with string,
            # that exists in db.
            return str(value)
        raise InvalidProtocol(protocol=value)
    except (ValueError, TypeError):
        if value.lower() in supported_protocols:
            return value.lower()
        raise InvalidProtocol(protocol=value)
    except AttributeError:
        raise InvalidProtocol(protocol=value)

def _validate_no_whitespace(data):
    if re.search(r'\s', data):
        msg = _("'%s' contains whitespace") % data
        raise InvalidInsideAddress2(inside_addr=data,msg=msg)
    return data

def convert_validate_ip_address(data, valid_values=None):
    try:
        ip = netaddr.IPAddress(_validate_no_whitespace(data),
                               flags=netaddr.core.ZEROFILL)
        if ':' not in data and data.count('.') != 3:
            msg = _("'%s' is not a valid IP address") % data
            raise InvalidInsideAddress2(inside_addr=data,msg=msg)
        if ip.version == 4 and str(ip) != data:
            msg = _("'%(data)s' is not an accepted IP address, "
                    "'%(ip)s' is recommended") % {"data": data, "ip": ip}
            raise InvalidInsideAddress2(inside_addr=data,msg=msg)
    except Exception:
        msg = _("'%s' is not a valid IP address") % data
        raise InvalidInsideAddress2(inside_addr=data,msg=msg)

def _validate_portforwardings(data, valid_values=None):
    if not isinstance(data, list):
        msg = _("Invalid data format for portforwarding: '%s'") % data
        raise InvalidInput(command=data,msg=msg)


supported_protocols = ['tcp', 'udp']


PORTFORWARDINGS = 'portforwardings'

RESOURCE_ATTRIBUTE_MAP = {
    PORTFORWARDINGS: {
        'outside_port': {'allow_post': True, 'allow_put': True,
                         'convert_to': convert_validate_port_value,
                         'is_visible': True,
                         'primary_key': True},
        'inside_addr': {'allow_post': True, 'allow_put': True,
                        'is_visible': True,
                        'convert_to': convert_validate_ip_address,
                        'primary_key': True},
        'inside_port': {'allow_post': True, 'allow_put': True,
                        'convert_to': convert_validate_port_value,
                        'is_visible': True,
                        'primary_key': True},
        'protocol': {'allow_post': True, 'allow_put': True,
                     'convert_to': convert_validate_protocol,
                     'is_visible': True,
                     'primary_key': True},
    },
}"""


def _validate_portforwardings(data, valid_values=None):
    if not isinstance(data, list):
        msg = _("Invalid data format for portforwarding: '%s'") % data
        raise webob.exc.HTTPBadRequest(msg)
#        LOG.debug(msg)
#        return msg

    expected_keys = ['protocol', 'outside_port',
                     'inside_addr', 'inside_port']
    portfwds = []
    for portfwd in data:
        msg = attributes._verify_dict_keys(expected_keys, portfwd)
        if msg:
            raise webob.exc.HTTPBadRequest(msg)
#            LOG.debug(msg)
#            return msg
            #raise InvalidInput(portfwd=portfwd, msg=msg)
        msg = attributes._validate_range(portfwd['outside_port'], (0, 65535))
        if msg:
            raise webob.exc.HTTPBadRequest(msg)
#            LOG.debug(msg)
#            return msg
            #raise InvalidPortValue(port=portfwd['outside_port'], msg=msg)
        msg = attributes._validate_ip_address(portfwd['inside_addr'])
        if msg:
            raise webob.exc.HTTPBadRequest(msg)
#            LOG.debug(msg)
#            return msg
        msg = attributes._validate_range(portfwd['inside_port'], (0, 65535))
        if msg:
            raise webob.exc.HTTPBadRequest(msg)
#            LOG.debug(msg)
#            return msg
            #raise InvalidPortValue(portfwd['inside_port'], msg=msg)
        msg = attributes._validate_values(portfwd['protocol'].upper(), ('TCP', 'UDP'))
        if msg:
            raise webob.exc.HTTPBadRequest(msg)
#            LOG.debug(msg)
#            return msg
            #raise InvalidProtocol(protocol=portfwd['protocol'].upper(), msg=msg)
        if portfwd in portfwds:
            raise DuplicatePortforwardingRuleInRequest(portfwds=portfwds)
#            msg = _("Duplicate portforwarding '%s'") % portfwd
#            LOG.debug(msg)
#            return msg
            #raise InvalidInput(portfwd=portfwd, msg=msg)
#        portfwds.append(portfwd)

attributes.validators['type:portforwardings'] = (_validate_portforwardings)

# Attribute Map
EXTENDED_ATTRIBUTES_2_0 = {
    'routers': {
        "portforwardings": {'allow_post': True, 'allow_put': True,
                            'validate': {'type:portforwardings': None},
                            'convert_to': attributes.convert_none_to_empty_list,
                            'convert_list_to': attributes.convert_kvp_list_to_dict,
                            'default': attributes.ATTR_NOT_SPECIFIED,
                            'is_visible': True},
    }
}


class Portforwardings(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Port Forwarding"

    @classmethod
    def get_alias(cls):
        return "portforwarding"

    @classmethod
    def get_description(cls):
        return "Expose internal TCP/UDP port to external network"

    @classmethod
    def get_updated(cls):
        return "2013-02-01T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            attributes.PLURALS.update({'portforwardings': 'portforwarding'})
            return EXTENDED_ATTRIBUTES_2_0
#            return dict(list(EXTENDED_ATTRIBUTES_2_0.items()) +
#                        list(RESOURCE_ATTRIBUTE_MAP.items()))
        else:
            return {}
"""    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/neutron/portforwarding/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2013-12-04T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        LOG.debug(_("Call class method get_resources: '%s'") % cls)
        my_plurals = [(key, key[:-1]) for key in RESOURCE_ATTRIBUTE_MAP.keys()]
        LOG.debug(_("get_resources my_plurals var: '%s'") % my_plurals)
        attributes.PLURALS.update(dict(my_plurals))
        exts = []
        plugin = manager.NeutronManager.get_plugin()
        resource_name = 'portforwarding'
        collection_name = resource_name.replace('_', '-') + "s"
        params = RESOURCE_ATTRIBUTE_MAP.get(resource_name + "s", dict())
        LOG.debug(_("get_resources params var: '%s'") % params)
        resource_registry.register_resource_by_name(resource_name)
        controller = base.create_resource(collection_name,
                                          resource_name,
                                          plugin, params, allow_bulk=True,
                                          allow_pagination=True,
                                          allow_sorting=True)
        LOG.debug(_("get_resources controller var: '%s'") % controller)
        ex = extensions.ResourceExtension(collection_name,
                                          controller,
                                          attr_map=params)
        LOG.debug(_("get_resources ex var: '%s'") % ex)
        exts.append(ex)
        LOG.debug(_("get_resources exts var: '%s'") % exts)
        return exts

    def update_attributes_map(self, attributes):
        LOG.debug(_("Call update_attribute_map, attributes var: '%s'") % attributes)
        super(Portforwardings, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return dict(list(EXTENDED_ATTRIBUTES_2_0.items()) +
                        list(RESOURCE_ATTRIBUTE_MAP.items()))
        else:
            return {}"""