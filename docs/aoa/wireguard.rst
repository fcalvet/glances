.. _wireguard:

WireGuard
======

If you use ``WireGuard``, Glances can help you to monitor one interface. This requires glances to run as root.


.. image:: ../_static/wireguard.png

It is disabled by default, you have enable it and configure the interface you wish to monitor. It is possible to define limits and actions from the configuration file
under the ``[wireguard]`` section:

.. code-block:: ini

    [wireguard]
    disable=False
    interface=wg0

