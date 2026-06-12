.. _libsuricata:

LibSuricata and Plugins
=======================

Using Suricata as a Library
---------------------------

The ability to turn Suricata into a library that can be utilized in other tools
is currently a work in progress, tracked by Redmine Ticket #2693:
https://redmine.openinfosecfoundation.org/issues/2693.

Plugins
-------

A related work are Suricata plugins, also in progress and tracked by Redmine
Ticket #4101: https://redmine.openinfosecfoundation.org/issues/4101.

Plugins can be used by modifying the suricata.yaml ``plugins`` section to include
the path of the dynamic library to load.

Plugins should export a ``SCPluginRegister`` function that will be the entry point
used by Suricata.

Application-layer plugins
~~~~~~~~~~~~~~~~~~~~~~~~~

Application layer plugins can be added as demonstrated by example
https://github.com/OISF/suricata/blob/main/examples/plugins/altemplate/

The plugin code contains the same files as an application layer in the source tree:
  - alname.rs : entry point of protocol with its registration
  - detect.rs : signature keywords
  - lib.rs : list the files in the rust module
  - log.rs : logging to eve.json
  - parser.rs : parsing functions

These files will have different ``use`` statements, targeting the suricata crate.

.. attention:: A plugin should not use rust structures from suricata crate if they are not repr(C), especially JsonBuilder.

This is because the rust compiler does not guarantee the structure layout unless you specify this representation.
Thus, the plugin may expect the ``JsonBuilder`` fields at different offsets than they are supplied by Suricata at runtime.
The solution is to go through the ``JsonBuilder`` C API which uses an opaque pointer.

And the plugin contains also additional files:
  - plugin.rs : defines the entry point of the plugin -- ``SCPluginRegister``

``SCPluginRegister`` should register a callback that should then call ``SCPluginRegisterAppLayer``
passing a ``SCAppLayerPlugin`` structure to Suricata.
It should also call ``suricata::plugin::init();`` to ensure the plugin has initialized
its value of the Suricata Context. This is a structure needed by rust, to call some C functions,
that cannot be found at compile time because of circular dependencies, and are therefore
resolved at runtime.

The ``SCPlugin`` begins by a version number ``SC_API_VERSION`` for runtime compatibility
between Suricata and the plugin.

Declaring Landlock permissions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When Landlock sandboxing is enabled (see :ref:`landlock`), Suricata
restricts the set of files and network ports the process can access.
A plugin that needs to read or write outside the standard Suricata
directories, or that opens network sockets, can declare its
requirements through the optional ``LandlockEnable`` callback on
``SCPlugin``:

.. code-block:: c

   #include "util-landlock.h"

   static void MyPluginLandlockEnable(struct landlock_ruleset *ruleset)
   {
       SCLandlockGrantReadPath(ruleset, "/etc/my-plugin/");
       SCLandlockGrantWritePath(ruleset, "/var/lib/my-plugin/");
       SCLandlockGrantNetConnectTCP(ruleset, 5044);
   }

   const SCPlugin PluginRegistration = {
       .version = SC_API_VERSION,
       /* ... */
       .Init = MyPluginInit,
       .LandlockEnable = MyPluginLandlockEnable,
   };

The callback is invoked once, just before the sandbox is enforced.
``ruleset`` is an opaque handle: callbacks must only use the
``SCLandlockGrant*`` helpers declared in ``util-landlock.h``. The
``LandlockEnable`` field may be left ``NULL`` when no extra
permissions are required.

The network grant helpers silently no-op on kernels whose Landlock ABI
does not support network rules, so callbacks do not need to guard them.

Known limitations are:

- Plugins can only use simple logging as defined by ``EveJsonSimpleTxLogFunc``
  without suricata.yaml configuration, see https://github.com/OISF/suricata/pull/11160
- Keywords cannot use validate callbacks, see https://redmine.openinfosecfoundation.org/issues/5634

.. attention:: A pure rust plugin needs to be compiled with ``RUSTFLAGS=-Clink-args=-Wl,-undefined,dynamic_lookup``

This is because the plugin will link dynamically at runtime the functions defined in Suricata runtime.
You can define this rust flag in a ``.cargo/config.toml`` file.
