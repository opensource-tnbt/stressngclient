import argparse
import os
import random
import re
import signal
import socket
import string
import struct
import subprocess
import sys
import time

import zmq

from conf import merge_spec
from conf import settings as S

#import cloud_agent_backend as backend
import proto.agent_pb2 as agent
import proto.crud_pb2 as crud
import proto.dynamic_result_pb2 as dynamic_result
import proto.tdigest_pb2 as tdigest
import proto.threshold_pb2 as threshold
import proto.node_pb2 as node
import proto.result_pb2 as result_pb2


def enum(**enums):
    return type('Enum', (), enums)


###
# Protocol Constants
###

IcpProtocolId = b'ICPA02'


IcpMessageType = enum(UNKNOWN=0x00,
                      HELLO=0x01,
                      CREATE=0xA0,
                      CREATE_OK=0xA1,
                      READ=0xB0,
                      READ_OK=0xB1,
                      UPDATE=0xC0,
                      UPDATE_OK=0xC1,
                      DELETE=0xD0,
                      DELETE_OK=0xD1,
                      ERROR=0xE0,
                      NOTIFICATION=0xFF)

IcpConfigKeys = [
    'config.callback',
    'config.result_sink',
]

IcpSysinfoKeys = [
    'sysinfo.ncpus',
    'sysinfo.physmem',
    'sysinfo.freemem',
    'sysinfo.cachelinesize',
    'sysinfo.disks',
    'sysinfo.interfaces',
    'sysinfo.uuid',
]

IcpCpuKeys = [
    'generator.cpu.utilization',
    'generator.cpu.running',
]

IcpMemoryKeys = [
    'generator.memory.buffer_size',
    'generator.memory.block_size',
    'generator.memory.reads_per_sec',
    'generator.memory.read_threads',
    'generator.memory.writes_per_sec',
    'generator.memory.write_threads',
    'generator.memory.running'
]

IcpBlockKeys = [
    'generator.block.aio_max',
    'generator.block.mode',
    'generator.block.device',
    'generator.block.device_size',
    'generator.block.file_template',
    'generator.block.file_size',
    'generator.block.block_size',
    'generator.block.reads_per_sec',
    'generator.block.writes_per_sec',
    'generator.block.running'
]

IcpNetworkKeys = [
    'generator.network.server.port',
    'generator.network.server.threads',
    'generator.network.client.remote.host',
    'generator.network.client.remote.port',
    'generator.network.client.protocol',
    'generator.network.client.connections',
    'generator.network.client.reads_per_sec',
    'generator.network.client.read_size',
    'generator.network.client.writes_per_sec',
    'generator.network.client.write_size',
    'generator.network.client.threads',
    'generator.network.client.running',
    'generator.network.client.targets'
]

ClientPublicKey = 'Yne@$w-vo<fVvi]a<NY6T1ed:M$fCG*[IaLV{hID'
ClientSecretKey = 'D:)Q[IlAW!ahhC2ac:9*A}h:p?([4%wOTJ%JR%cs'

# Map keys to protobuf objects
IcpProtobufKeys = {
    'config.callback': agent.Endpoint,
    'results.sink': agent.Endpoint,
    'ntp.server': agent.Endpoint,
    'stats.rtts': tdigest.Result,
    'tdigest-[0-9a-fA-F]+': tdigest.Result,
    'threshold-[0-9a-fA-F]+': threshold.Result,
    'clock.rtts': tdigest.Result,
    'vdev-[0-9]+': agent.VirtualDevice,
    'sysinfo.node': node.InstanceInfo,
    'tag-[0-9a-fA-F]+': result_pb2.Multimap,
}


###
# Utility functions/classes
###

def show_config(client):

    def print_status(client, key):
        print('{:<41s}:{:>38}'.format(
            key,
            client.get(key)))

    list(map(lambda k: print_status(client, k), IcpConfigKeys))
    list(map(lambda k: print_status(client, k), IcpSysinfoKeys))
    list(map(lambda k: print_status(client, k), IcpCpuKeys))
    list(map(lambda k: print_status(client, k), IcpBlockKeys))
    list(map(lambda k: print_status(client, k), IcpMemoryKeys))
    list(map(lambda k: print_status(client, k), IcpNetworkKeys))


def get_config(client):
    config = dict()

    def add_config_key(key):
        config[key] = client.get(key)

    list(map(lambda k: add_config_key(k), IcpConfigKeys))
    list(map(lambda k: add_config_key(k), IcpSysinfoKeys))
    list(map(lambda k: add_config_key(k), IcpCpuKeys))
    list(map(lambda k: add_config_key(k), IcpBlockKeys))
    list(map(lambda k: add_config_key(k), IcpMemoryKeys))
    list(map(lambda k: add_config_key(k), IcpNetworkKeys))

    return config


def dump(message):
    dump_map = {
        type(None): IcpMessageType.HELLO,
        CreateRequest: IcpMessageType.CREATE,
        ReadRequest: IcpMessageType.READ,
        UpdateRequest: IcpMessageType.UPDATE,
        DeleteRequest: IcpMessageType.DELETE
    }

    if type(message) not in dump_map:
        raise TypeError('Unsupported message type: {0}'.format(type(message)))

    return (dump_map[type(message)], message.data if message else None)


def load(kind, data=None):
    load_map = {
        IcpMessageType.CREATE: crud.Create,
        IcpMessageType.CREATE_OK: crud.CreateOk,
        IcpMessageType.READ: crud.Read,
        IcpMessageType.READ_OK: crud.ReadOk,
        IcpMessageType.UPDATE: crud.Update,
        IcpMessageType.UPDATE_OK: crud.UpdateOk,
        IcpMessageType.DELETE: crud.Delete,
        IcpMessageType.DELETE_OK: crud.DeleteOk,
        IcpMessageType.ERROR: crud.Error,
        IcpMessageType.NOTIFICATION: crud.Notification
    }

    if kind not in load_map:
        raise TypeError('Unsupported data type: {0}'.format(kind))

    msg = load_map[kind]()
    msg.ParseFromString(data)

    return msg


def get_value_from_data(data):
    av_fields = ['f64',
                 'u64',
                 's64',
                 'boolean',
                 'str',
                 'bin']

    av = agent.Value()
    av.ParseFromString(data)

    for field in av_fields:
        if av.HasField(field):
            return getattr(av, field)

    return None


def get_data_from_value(value):
    if value is None:
        return None

    data = agent.Value()

    if isinstance(value, bool):
        data.boolean = value
    elif isinstance(value, float):
        data.f64 = value
    elif isinstance(value, int):
        if value >= 0:
            data.u64 = value
        else:
            data.s64 = value
    else:
        # Check to see if the leading characters are printable
        # If they are, presume this is a string, otherwise
        # treat it as binary data
        max_char = min(len(value), 32)
        if all(c in string.printable for c in value[:max_char]):
            data.str = value
        else:
            data.bin = value

    return data.SerializeToString()


###
# CRUD Request objects
###

class ApiRequest(object):
    def __init__(self, key, value=None, token=None):
        self.key = key
        self.value = value
        self.token = token

    @property
    def data(self):
        return None

class CreateRequest(ApiRequest):

    def __init__(self, parent, data_type, data_value, token=None):
        self.parent = parent
        if data_type != None:
            self.dtype = data_type
        else:
            self.dtype = 0
        self.dvalue = data_value
        self.token = token

    @property
    def data(self):
        msg = crud.Create()
        msg.parent = self.parent
        msg.type = self.dtype
        msg.data = get_data_from_value(self.dvalue)
        if self.token:
            msg.token = self.token
        return msg.SerializeToString()


class ReadRequest(ApiRequest):

    @property
    def data(self):
        msg = crud.Read()
        msg.key = self.key
        if self.token:
            msg.token = self.token
        return msg.SerializeToString()


class UpdateRequest(ApiRequest):

    @property
    def data(self):
        msg = crud.Update()
        msg.key = self.key
        msg.data = get_data_from_value(self.value)
        if self.token:
            msg.token = self.token
        return msg.SerializeToString()


class DeleteRequest(ApiRequest):

    def __init__(self, key, token=None):
        self.key = key
        self.token = token

    @property
    def data(self):
        msg = crud.Delete()
        msg.key = self.key
        if self.token:
            msg.token = self.token

        return msg.SerializeToString()




###
# Wrapper objects for protobuf encoding
###

class DynamicResultConfig(object):

    def is_valid_function(self, fn):
        if (fn == dynamic_result.DX
                or fn == dynamic_result.DXDY
                or fn == dynamic_result.DXDT):
            return True
        return False

    @property
    def data(self):
        return self._config.SerializeToString()

    @property
    def data_type(self):
        raise NotImplementedError()


class TdigestConfig(DynamicResultConfig):

    def __init__(self, function, x_stat, y_stat=None):
        if not self.is_valid_function(function):
            raise TypeError('Invalid function: {0}'.format(function))

        td = tdigest.Config()
        td.function = function
        td.x_stat = x_stat
        if y_stat is not None:
            td.y_stat = y_stat

        self._config = td

    @property
    def data_type(self):
        return dynamic_result.TDIGEST


class ThresholdConfig(DynamicResultConfig):

    def __init__(self, function, value, relation, x_stat, y_stat=None):
        if not self.is_valid_function(function):
            raise TypeError('Invalid function: {0}'.format(function))

        if not self.is_valid_relation(relation):
            raise TypeError('Invalid relation: {0}'.format(relation))

        th = threshold.Config()
        th.function = function
        th.threshold = value
        th.relation = relation
        th.x_stat = x_stat
        if y_stat is not None:
            th.y_stat = y_stat

        self._config = th

    def is_valid_relation(self, relation):
        if (relation == threshold.GREATER_THAN
                or relation == threshold.GREATER_THAN_OR_EQUAL
                or relation == threshold.LESS_THAN
                or relation == threshold.LESS_THAN_OR_EQUAL):
            return True
        return False

    @property
    def data_type(self):
        return dynamic_result.THRESHOLD


class Endpoint(object):

    def __init__(self, thing1, thing2=None):
        if thing1 is not None and thing2 is None:
            uri = thing1  # treat thing1 as a URI
            protocol = port = None
        elif thing1 is not None and thing2 is not None:
            # treat input as protocol and port
            uri = None
            protocol = thing1
            port = thing2
        elif thing1 is None and thing2 is None:
            uri = None
            protocol = None
            port = 0
        else:
            raise ValueError('Most specify protocol and port OR uri')

        ep = agent.Endpoint()

        if uri is not None:
            tokens = re.split(':\/\/|:', uri)

            ep.protocol = self._get_protocol_enum(tokens[0])
            ep.address = socket.gethostbyname(tokens[1])
            ep.port = int(tokens[2]) & 0xffff
        else:
            ep.protocol = self._get_protocol_enum(protocol)
            ep.port = int(port) & 0xffff

        self._endpoint = ep

    def _get_protocol_enum(self, protocol):
        protocol_map = {
            'tcp': agent.Endpoint.TCP,
            'udp': agent.Endpoint.UDP,
            None: agent.Endpoint.NONE
        }

        return (protocol_map[protocol])

    @property
    def data(self):
        return self._endpoint.SerializeToString()


class RequestSocket(object):
    '''
    This is a context manager for a ZeroMQ request socket
    '''

    def __init__(self, ctx, endpoint, server_key=None, timeout=None):
        if not timeout:
            timeout = 5000  # milliseconds

        self._socket = ctx.socket(zmq.REQ)

        self._socket.setsockopt(zmq.SNDTIMEO, timeout)
        self._socket.setsockopt(zmq.RCVTIMEO, timeout)

        if server_key:
            self._socket.curve_secretkey = ClientSecretKey
            self._socket.curve_publickey = ClientPublicKey
            self._socket.curve_serverkey = server_key

        self._socket.connect(endpoint)

    def __enter__(self):
        return self._socket

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if exc_type:
            # Forcibly close the socket
            self._socket.close(linger=0)
        return False


class IcpControlClient(object):
    '''
    Object for talking to the inceptiond control service
    '''

    def __init__(self, endpoint, skip_session=None, server_key=None, token=None):
        self._context = zmq.Context()
        self._endpoint = endpoint
        self._server_key = server_key
        self._session = None
        self._token = None
        self._disconnected = False

        if skip_session:
            # verify the other side is really there
            self.hello()
        elif token:
            self._token = token
        else:
            # Try to create a session.  If that fails, fall back to a
            # session free client
            done = False
            while not done:
                reply = self._do_request([CreateRequest('config.sessions', 0, '')])
                if type(reply[0]) == crud.CreateOk:
                    self._session = reply[0].key
                    self._token = reply[0].token
                    done = True
                elif type(reply[0]) == crud.Error and reply[0].code == 16:
                    print('Agent is resetting...')
                    time.sleep(1)
                else:
                    print((str(reply[0])))
                    print('Unable to create session.  Client is read-only.')
                    done = True

    def __del__(self):
        if self._disconnected:
            return

#        if (self._session):
#            try:
#                # XXX: Disable the watchdog before deleting the session.
#                # This prevents a potential double reset should the delete and
#                # watchdog timeout occur simultaneously.  This mainly benefits
#                # the *next* session which won't need to wait for both resets.
#                self._do_request([
#                    UpdateRequest('config.watchdog', 0xffffffffffffffff, self._token),
#                    DeleteRequest(self._session, self._token)
#                ])
#            except:
#                pass

    @property
    def endpoint(self):
        return self._endpoint

    @property
    def token(self):
        return self._token

    @property
    def request_id(self):
        self.reply_id = (int(time.time() * 1000000) & 0xffffffff)
        return self.reply_id

    def disconnect(self):
        if self._token:
            print('Current session token = %s' % self._token)
        self._disconnected = True

    def _do_request(self, requests):
        tosend = [IcpProtocolId, struct.pack('Q', self.request_id)]
        for req in requests:
            #print("DOING REQUEST")
            msg_type, msg_data = dump(req)
            #print(msg_type)
            #print(msg_data)
            tosend.append(struct.pack('!H', msg_type))
            if msg_data:
                tosend.append(msg_data)

        # Retry requests with an exponential backoff up to our timeout limit
        reply = None
        timeout = 1024
        timeout_limit = timeout * 8
        while timeout <= timeout_limit:
            try:
                with RequestSocket(self._context, self._endpoint, self._server_key, timeout) as s:
                    s.send_multipart(tosend)
                    start = time.time()
                    reply = s.recv_multipart()
                    response_time = time.time() - start
                    if response_time > 0.1:
                        sys.stderr.write("WARNING: response from %s was slow (%f seconds)\n"
                                         % (self._endpoint, response_time))

            except zmq.error.Again as e:
                timeout += timeout
                continue
            else:
                break

        if not reply and timeout >= timeout_limit:
            # We exhausted all of our retries
            raise IOError('Request to %s failed: operation timed out' % self._endpoint)

        return (self._unpack_reply(reply) if reply else None)

    def _unpack_reply(self, reply):
        if not isinstance(reply, list):
            raise TypeError('reply must be a list')

        # Check headers
        proto = reply.pop(0)
        assert proto == IcpProtocolId

        msg_id = struct.unpack('Q', reply.pop(0))[0]
        assert msg_id == self.reply_id

        # Handle type/data pairs
        msgs = list()

        while len(reply):
            msg_type = struct.unpack('!H', reply.pop(0))[0]
            if msg_type == IcpMessageType.HELLO:
                msgs.append(None)
            else:
                msgs.append(load(msg_type, reply.pop(0)))

        return msgs

    def hello(self):
        '''
        Send a hello message to the service and verify the response
        '''
        reply = self._do_request([None])
        return (reply[0] is None)

    def decode_msg(self, msg):
        value = get_value_from_data(msg.data)
        for pattern, kind in IcpProtobufKeys.items():
            if value and re.search(pattern, msg.key):
                obj = kind()
                obj.ParseFromString(value)
                return obj
        return value

    def get_one(self, key):
        '''
        Get the current value of key
        '''
        reply = self._do_request([ReadRequest(key)])
        if type(reply[0]) == crud.Error:
            raise RuntimeError(str(reply[0]))

        return self.decode_msg(reply[0])

    def get_many(self, keys):
        reply = self._do_request([ReadRequest(k) for k in keys])
        result = dict()
        for msg in reply:
            if type(msg) == crud.Error:
                sys.stdout.write(str(msg))
            else:
                result[msg.key] = self.decode_msg(msg)

        return result

    def get(self, thing):
        if type(thing) is list:
            return self.get_many(thing)
        else:
            return self.get_one(thing)

    def print_children(self, parent):
        '''
        Retrieve all the child data in two requests.  The first request
        gets the child handles; the second retrieves their value.
        '''
        results = self.get(['%s.%s' % (parent, c.strip(',')) for c in self.get(parent).split()])
        for k, v in sorted(results.items()):
            print('%s:' % k, v)

    def set_one(self, key, value):
        reply = self._do_request([UpdateRequest(key, value, self._token)])
        if type(reply[0]) == crud.Error:
            raise RuntimeError(str(reply[0]))

        return True

    def set_many(self, config, prefix=None):
        #print("Coming here")
#        requests = []
#        for k_v in iter(config.items()):
#            if prefix:
#                requests.append(UpdateRequest('%s.%s' % (prefix, k_v[0])))
#            else:
#                requests.append(UpdateRequest(k_v[0], k_v[1], self._token))
#        print(requests)
        reply = self._do_request(
                [UpdateRequest('%s.%s' % (prefix, k_v[0]) if prefix else k_v[0],k_v[1],
                                             self._token) for k_v in iter(config.items())])
        result = dict()
        for msg in reply:
            if type(msg) == crud.Error:
                sys.stdout.write(str(msg))
            else:
                result[msg.key] = True

        return len(result) == len(config)

    def set(self, thing1, thing2=None):
        if type(thing1) is dict:
            return self.set_many(thing1, thing2)
        else:
            return self.set_one(thing1, thing2)

    def create(self, parent, value, kind=None):
        reply = self._do_request([CreateRequest(parent, kind, value, self._token)])
        if type(reply[0]) == crud.Error:
            raise RuntimeError(str(reply[0]))

        return True, reply[0].key

    def update(self, key, value):
        reply = self._do_request([UpdateRequest(key, value, self._token)])
        if type(reply[0]) == crud.Error:
            raise RuntimeError(str(reply[0]))

        return True

    def delete(self, key):
        reply = self._do_request([DeleteRequest(key, self._token)])
        if type(reply[0]) == crud.Error:
            raise RuntimeError(str(reply[0]))

        return True

    def bulk_request(self, requests):
        if type(requests) is not list:
            raise TypeError('Need a list of requests')

        reply = self._do_request(requests)
        result = dict()
        for msg in reply:
            if type(msg) == crud.Error:
                sys.stdout.write(str(msg))
            else:
                result[msg.key] = self.decode_msg(msg)
        #print(result)
        return True


###
# Test Functions
###
def stop_and_clear(clients):
    '''
    Stop all running generators and delete any configured results
    '''
    for client in clients:
        client.set('generator.cpu.running', False)
        client.set('generator.block.running', False)
        client.set('generator.memory.running', False)
        client.set('generator.network.client.running', False)

def cpu_test(client):
    client.set('generator.cpu.utilization', float(S.getValue('CPU_UTILIZATION')))
    client.set('generator.cpu.running', True)

def block_test(client):
    return
    config = {
 #       'block_size': int(S.getValue('BLOCK_SIZE')),
        'reads_per_sec': int(S.getValue('BLOCK_READS_PER_SEC')),
        'writes_per_sec': int(S.getValue('BLOCK_WRITES_PER_SEC'))
    }

    client.set('generator.block.file_size', 32 * 1024 * 1024)
    for key, value in config.items():
        client.set('generator.block.{0}'.format(key), value)

    client.set('generator.block.running', True)

def mem_test(client):
    config = {
        'buffer_size': int(S.getValue('MEMORY_BLOCKS')) * 1024 * 1024,
#        'block_size': int(S.getValue('MEMORY_BLOCK_SIZE')),
        'reads_per_sec': int(S.getValue('MEMORY_READS_PER_SEC')),
        'writes_per_sec': int(S.getValue('MEMORY_WRITES_PER_SEC')),
    }

    for key, value in config.items():
        client.set('generator.memory.{0}'.format(key), value)

    client.set('generator.memory.running', True)


def net_test(client):
    config = {
        'generator.network.server.threads': 2,
        'generator.network.client.threads': 2
    }

    client.set(config)

    uri = agent.GenericUri()
    uri.scheme = agent.GenericUri.FIREHOSE_UDP
    uri.host = S.getValue('NETWORK_REMOTE_IP')
    uri.port = 3357

    config = {
        'remote.host': S.getValue('NETWORK_REMOTE_IP'),
        'protocol': S.getValue('NETWORK_CLIENT_PROTOCOL'),
        'connections': int(S.getValue('NETWORK_CLIENT_CONNECTIONS')),
        'reads_per_sec': int(S.getValue('NETWORK_CLIENT_READS_PER_SEC')),
        'read_size': int(S.getValue('NETWORK_CLIENT_READ_SIZE')),
        'writes_per_sec': int(S.getValue('NETWORK_CLIENT_WRITES_PER_SEC')),
        'write_size': int(S.getValue('NETWORK_CLIENT_WRITE_SIZE'))
    }

    client.set(config, 'generator.network.client')
    #client.set('generator.network.client.targets',S.getValue('NETWORK_REMOTE_IP'))

    client.set('generator.network.client.running', True)



class CloudAgentClient(IcpControlClient):
    '''
    Object for Sending requests to inceptiond control service
    '''

    def _unpack_reply(self, reply):
        if not isinstance(reply, list):
            raise TypeError('reply must be a list')

        # Check headers
        proto = reply.pop(0)
        assert proto == IcpProtocolId

        reply.pop(0)

        # Handle type/data pairs
        msgs = list()

        while len(reply):
            msg_type = struct.unpack('!H', reply.pop(0))[0]
            if msg_type == IcpMessageType.HELLO:
                msgs.append(None)
            else:
                msgs.append(load(msg_type, reply.pop(0)))

        return msgs

    def _get_packed_bytes(self, nb_bytes):
        return struct.pack('B' * nb_bytes, *[random.randint(0, 255)
                                             for i in range(nb_bytes)])

    def _do_fuzz_request(self):
        x = random.randint(0, 3)
        if x == 0:
            request = self._get_fuzz_request_0()
        elif x == 1:
            request = self._get_fuzz_request_1()
        elif x == 2:
            request = self._get_fuzz_request_2()
        elif x == 3:
            request = self._get_fuzz_request_3()

        reply = None
        with RequestSocket(self._context, self._endpoint) as s:
            s.send_multipart(request)

            try:
                reply = s.recv_multipart()
            except zmq.error.Again:
                pass

        toreturn = self._unpack_reply(reply) if reply else None

        if toreturn is None:
            print('No reply received for: ', request)

        return toreturn

    def raw_request(self, tosend):
        reply = None
        with RequestSocket(self._context, self._endpoint) as s:
            s.send_multipart(tosend)

            reply = s.recv_multipart()

        return (self._unpack_reply(reply) if reply else None)


class OverException(Exception):
    pass

def parse_arguments():
    """
    Parse command line arguments.
    """
    class _ValidateFileAction(argparse.Action):
        """Validate a file can be read from before using it.
        """
        def __call__(self, parser, namespace, values, option_string=None):
            if not os.path.isfile(values):
                raise argparse.ArgumentTypeError(
                    'the path \'%s\' is not a valid path' % values)
            elif not os.access(values, os.R_OK):
                raise argparse.ArgumentTypeError(
                    'the path \'%s\' is not accessible' % values)
    parser = argparse.ArgumentParser(prog=__file__, formatter_class=
                                     argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--version', action='version', version='%(prog)s 0.1')
    parser.add_argument('--conf-file', action=_ValidateFileAction,
            help='settings file')
    args = vars(parser.parse_args())

    return args

_CURR_DIR = os.path.dirname(os.path.realpath(__file__))

def main():
    args = parse_arguments()
    S.load_from_dir(os.path.join(_CURR_DIR, 'conf'))
    if args['conf_file']:
        settings.load_from_file(args['conf_file'])
    endpoints = S.getValue('ENDPOINTS')
    clients = []
    for endpoint in endpoints:
        enp = 'tcp://' + endpoint + ':' + S.getValue('EP_CONTROL_PORT')
        client = CloudAgentClient(enp)
        try:
            clients.append(client)
            cpu_test(client)
            mem_test(client)
            block_test(client)
            net_test(client)
        except (RuntimeError, TypeError, NameError, OverException, IOError) as exc:
            print(exc)
            pass
    start_time = time.time()
    while True:
        if S.getValue('TIMED_RUN'):
            time.sleep(float(S.getValue('RUNTIME')))
            stop_and_clear(clients)
            sys.exit()
        else:
            try:
                time.sleep(60)
                step_time = time.time()
                print("Test Elapsed Duration is: {0}".format(step_time - start_time))
            except KeyboardInterrupt:
                stop_and_clear(clients)
                print("Bye")
                sys.exit()

if __name__ == "__main__":
    main()
