.. _wireguard:

WireGuard
======

If you use ``WireGuard``, Glances can help you to monitor one interface.


.. image:: ../_static/wireguard.png

It is possible to define limits and actions from the configuration file
under the ``[docker]`` section:

.. code-block:: ini

    [wireguard]
    disable=False
    interface=wg0

