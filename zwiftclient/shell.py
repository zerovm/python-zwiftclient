from errno import ENOENT
from genericpath import getsize
import signal
import logging
import socket
from sys import argv as sys_argv, exit
from swiftclient.exceptions import ClientException
from swiftclient.multithreading import MultiThreadingManager
from swiftclient import RequestException
from swiftclient import __version__ as client_version
from optparse import OptionParser, SUPPRESS_HELP
from os import environ
from swiftclient.shell import parse_args, immediate_exit, \
    split_headers
from swiftclient.utils import config_true_value
from swiftclient import shell as swiftshell
from zwiftclient.client import ZwiftConnection

st_delete_options = swiftshell.st_delete_options
st_delete_help = swiftshell.st_delete_help
st_delete = swiftshell.st_delete

st_download_options = swiftshell.st_download_options
st_download_help = swiftshell.st_download_help
st_download = swiftshell.st_download

st_list_options = swiftshell.st_list_options
st_list_help = swiftshell.st_list_help
st_list = swiftshell.st_list

st_stat_options = swiftshell.st_stat_options
st_stat_help = swiftshell.st_stat_help
st_stat = swiftshell.st_stat

st_post_options = swiftshell.st_post_options
st_post_help = swiftshell.st_post_help
st_post = swiftshell.st_post

st_upload_options = swiftshell.st_upload_options
st_upload_help = swiftshell.st_upload_help
st_upload = swiftshell.st_upload

st_capabilities_options = swiftshell.st_capabilities_options
st_capabilities_help = swiftshell.st_capabilities_help
st_capabilities = swiftshell.st_capabilities

st_info_options = swiftshell.st_info_options
st_info_help = swiftshell.st_info_help
st_info = swiftshell.st_info

swiftshell.BASENAME = 'zwift'


def get_conn(options):
    """
    Return a connection building it from the options.
    """
    return ZwiftConnection(options.auth,
                           options.user,
                           options.key,
                           retries=1,  # we do not want to retry jobs
                           auth_version=options.auth_version,
                           os_options=options.os_options,
                           snet=options.snet,
                           cacert=options.os_cacert,
                           insecure=options.insecure,
                           ssl_compression=options.ssl_compression)


st_exec_options = '''[--content-type <type>] [--exec-threads <thread>]
                     [--header <header>] [--object <container/object>]
'''
st_exec_help = '''
exec [options] config_file [config_file] [...]
    Executes ZeroVM job described by the configuration file
    Each file must contain one ZeroVM job configuration.
    For help on file format see ZeroCloud docs
'''.strip('\n')


def st_exec(parser, args, thread_manager):
    parser.add_option(
        '', '--content-type', dest='content_type', default='application/json',
        help='Set the MIME type of the job description file. '
             'Could be json job config, or zar/tar job archive, '
             'or even simple text script.')
    parser.add_option(
        '', '--exec-threads', type=int, default=10,
        help='Number of threads to use for executing jobs. '
        'Default is 10.')
    parser.add_option(
        '-H', '--header', action='append', dest='header',
        default=[], help='Set request headers with the syntax header:value. '
        ' This option may be repeated. Example -H "content-type:text/plain" '
        '-H "Content-Length: 4000"')
    parser.add_option(
        '', '--object', dest='obj_path',
        help='Execute job over specific Swift object url.')
    (options, args) = parse_args(parser, args)
    args = args[1:]
    if len(args) < 1:
        thread_manager.error(
            'Usage: %s exec %s\n%s', swiftshell.BASENAME, st_exec_options,
            st_exec_help)
        return

    def _exec_job(job, conn):
        path = job['path']
        content_type = job['content_type']
        try:
            exec_headers = {}
            # Merge the command line header options to the exec_headers
            exec_headers.update(split_headers(options.header, '',
                                              thread_manager))
            container = None
            obj = None
            if options.obj_path:
                container, obj = options.obj_path.split('/', 1)
            resp = {}
            body, headers = conn.exec_account(
                container, obj, open(path, 'rb'), content_type=content_type,
                content_length=getsize(path), headers=exec_headers,
                response_dict=resp)
            thread_manager.print_headers(headers,
                                         meta_prefix='x-object-meta-',
                                         exclude_headers=['content-encoding',
                                                          'vary', 'etag'],
                                         offset=18)
            thread_manager.print_msg(body)
        except OSError as err:
            if err.errno != ENOENT:
                raise
            thread_manager.error('Local file %r not found', path)

    create_connection = lambda: get_conn(options)
    exec_manager = thread_manager.queue_manager(
        _exec_job, options.exec_threads,
        connection_maker=create_connection)
    with exec_manager as exec_queue:
        try:
            for arg in args:
                exec_queue.put({'path': arg,
                                'content_type': options.content_type})
        except ClientException as err:
            if err.http_status != 404:
                raise
            thread_manager.error('Account not found')


def main(arguments=None):
    if arguments:
        argv = arguments
    else:
        argv = sys_argv

    version = client_version
    parser = OptionParser(version='%%prog %s' % version,
                          usage='''
usage: %%prog [--version] [--help] [--snet] [--verbose]
             [--debug] [--info] [--quiet] [--auth <auth_url>]
             [--auth-version <auth_version>] [--user <username>]
             [--key <api_key>] [--retries <num_retries>]
             [--os-username <auth-user-name>] [--os-password <auth-password>]
             [--os-tenant-id <auth-tenant-id>]
             [--os-tenant-name <auth-tenant-name>]
             [--os-auth-url <auth-url>] [--os-auth-token <auth-token>]
             [--os-storage-url <storage-url>] [--os-region-name <region-name>]
             [--os-service-type <service-type>]
             [--os-endpoint-type <endpoint-type>]
             [--os-cacert <ca-certificate>] [--insecure]
             [--no-ssl-compression]
             <subcommand> ...

Command-line interface to the OpenStack Swift API.

Positional arguments:
  <subcommand>
    delete               Delete a container or objects within a container.
    download             Download objects from containers.
    list                 Lists the containers for the account or the objects
                         for a container.
    post                 Updates meta information for the account, container,
                         or object; creates containers if not present.
    stat                 Displays information for the account, container,
                         or object.
    upload               Uploads files or directories to the given container
    capabilities         List cluster capabilities.
    exec                 Execute ZeroCloud job


Examples:
  %%prog -A https://auth.api.rackspacecloud.com/v1.0 -U user -K api_key stat -v

  %%prog --os-auth-url https://api.example.com/v2.0 --os-tenant-name tenant \\
      --os-username user --os-password password list

  %%prog --os-auth-token 6ee5eb33efad4e45ab46806eac010566 \\
      --os-storage-url https://10.1.5.2:8080/v1/AUTH_ced809b6a4baea7aeab61a \\
      list

  %%prog list --lh
'''.strip('\n') % globals())
    parser.add_option('-s', '--snet', action='store_true', dest='snet',
                      default=False, help='Use SERVICENET internal network.')
    parser.add_option('-v', '--verbose', action='count', dest='verbose',
                      default=1, help='Print more info.')
    parser.add_option('--debug', action='store_true', dest='debug',
                      default=False, help='Show the curl commands and results '
                      'of all http queries regardless of result status.')
    parser.add_option('--info', action='store_true', dest='info',
                      default=False, help='Show the curl commands and results '
                      ' of all http queries which return an error.')
    parser.add_option('-q', '--quiet', action='store_const', dest='verbose',
                      const=0, default=1, help='Suppress status output.')
    parser.add_option('-A', '--auth', dest='auth',
                      default=environ.get('ST_AUTH'),
                      help='URL for obtaining an auth token.')
    parser.add_option('-V', '--auth-version',
                      dest='auth_version',
                      default=environ.get('ST_AUTH_VERSION', '1.0'),
                      type=str,
                      help='Specify a version for authentication. '
                           'Defaults to 1.0.')
    parser.add_option('-U', '--user', dest='user',
                      default=environ.get('ST_USER'),
                      help='User name for obtaining an auth token.')
    parser.add_option('-K', '--key', dest='key',
                      default=environ.get('ST_KEY'),
                      help='Key for obtaining an auth token.')
    parser.add_option('-R', '--retries', type=int, default=5, dest='retries',
                      help='The number of times to retry a failed connection.')
    parser.add_option('--os-username',
                      metavar='<auth-user-name>',
                      default=environ.get('OS_USERNAME'),
                      help='OpenStack username. Defaults to env[OS_USERNAME].')
    parser.add_option('--os_username',
                      help=SUPPRESS_HELP)
    parser.add_option('--os-password',
                      metavar='<auth-password>',
                      default=environ.get('OS_PASSWORD'),
                      help='OpenStack password. Defaults to env[OS_PASSWORD].')
    parser.add_option('--os_password',
                      help=SUPPRESS_HELP)
    parser.add_option('--os-tenant-id',
                      metavar='<auth-tenant-id>',
                      default=environ.get('OS_TENANT_ID'),
                      help='OpenStack tenant ID. '
                      'Defaults to env[OS_TENANT_ID].')
    parser.add_option('--os_tenant_id',
                      help=SUPPRESS_HELP)
    parser.add_option('--os-tenant-name',
                      metavar='<auth-tenant-name>',
                      default=environ.get('OS_TENANT_NAME'),
                      help='OpenStack tenant name. '
                           'Defaults to env[OS_TENANT_NAME].')
    parser.add_option('--os_tenant_name',
                      help=SUPPRESS_HELP)
    parser.add_option('--os-auth-url',
                      metavar='<auth-url>',
                      default=environ.get('OS_AUTH_URL'),
                      help='OpenStack auth URL. Defaults to env[OS_AUTH_URL].')
    parser.add_option('--os_auth_url',
                      help=SUPPRESS_HELP)
    parser.add_option('--os-auth-token',
                      metavar='<auth-token>',
                      default=environ.get('OS_AUTH_TOKEN'),
                      help='OpenStack token. Defaults to env[OS_AUTH_TOKEN]. '
                           'Used with --os-storage-url to bypass the '
                           'usual username/password authentication.')
    parser.add_option('--os_auth_token',
                      help=SUPPRESS_HELP)
    parser.add_option('--os-storage-url',
                      metavar='<storage-url>',
                      default=environ.get('OS_STORAGE_URL'),
                      help='OpenStack storage URL. '
                           'Defaults to env[OS_STORAGE_URL]. '
                           'Overrides the storage url returned during auth. '
                           'Will bypass authentication when used with '
                           '--os-auth-token.')
    parser.add_option('--os_storage_url',
                      help=SUPPRESS_HELP)
    parser.add_option('--os-region-name',
                      metavar='<region-name>',
                      default=environ.get('OS_REGION_NAME'),
                      help='OpenStack region name. '
                           'Defaults to env[OS_REGION_NAME].')
    parser.add_option('--os_region_name',
                      help=SUPPRESS_HELP)
    parser.add_option('--os-service-type',
                      metavar='<service-type>',
                      default=environ.get('OS_SERVICE_TYPE'),
                      help='OpenStack Service type. '
                           'Defaults to env[OS_SERVICE_TYPE].')
    parser.add_option('--os_service_type',
                      help=SUPPRESS_HELP)
    parser.add_option('--os-endpoint-type',
                      metavar='<endpoint-type>',
                      default=environ.get('OS_ENDPOINT_TYPE'),
                      help='OpenStack Endpoint type. '
                           'Defaults to env[OS_ENDPOINT_TYPE].')
    parser.add_option('--os-cacert',
                      metavar='<ca-certificate>',
                      default=environ.get('OS_CACERT'),
                      help='Specify a CA bundle file to use in verifying a '
                      'TLS (https) server certificate. '
                      'Defaults to env[OS_CACERT].')
    default_val = config_true_value(environ.get('SWIFTCLIENT_INSECURE'))
    parser.add_option('--insecure',
                      action="store_true", dest="insecure",
                      default=default_val,
                      help='Allow swiftclient to access servers without '
                           'having to verify the SSL certificate. '
                           'Defaults to env[SWIFTCLIENT_INSECURE] '
                           '(set to \'true\' to enable).')
    parser.add_option('--no-ssl-compression',
                      action='store_false', dest='ssl_compression',
                      default=True,
                      help='This option is deprecated and not used anymore. '
                           'SSL compression should be disabled by default '
                           'by the system SSL library.')
    parser.disable_interspersed_args()
    (options, args) = parse_args(parser, argv[1:], enforce_requires=False)
    parser.enable_interspersed_args()

    commands = ('delete', 'download', 'list', 'post',
                'stat', 'upload', 'capabilities', 'info', 'exec')
    if not args or args[0] not in commands:
        parser.print_usage()
        if args:
            exit('no such command: %s' % args[0])
        exit()

    signal.signal(signal.SIGINT, immediate_exit)

    if options.debug or options.info:
        logging.getLogger("swiftclient")
        if options.debug:
            logging.basicConfig(level=logging.DEBUG)
        elif options.info:
            logging.basicConfig(level=logging.INFO)

    had_error = False

    with MultiThreadingManager() as thread_manager:
        parser.usage = globals()['st_%s_help' % args[0]]
        try:
            globals()['st_%s' % args[0]](parser, argv[1:], thread_manager)
        except (ClientException, RequestException, socket.error) as err:
            thread_manager.error(str(err))

        had_error = thread_manager.error_count

    if had_error:
        exit(1)


if __name__ == '__main__':
    main()
