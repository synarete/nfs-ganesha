#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# ganesha_prometheus_exporter.py - export NFS-Ganesha stats as Prometheus
#  metrics over HTTP.
#
# Copyright (c) 2022 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Author: Shachar Sharon <ssharon@redhat.com>
# -*- coding: utf-8 -*-

import sys
import time
import getopt
import prometheus_client
import prometheus_client.core
import Ganesha.glib_dbus_stats as ganesha_dbus  # type: ignore


class Collector:
    """Base class for NFS-ganesha metrics colletors.

    Implements common functionality to sub-collectors: exports metrics as
    Prometheus gauges with 'nfs_ganesha' and collector's sub-name as metrics
    name prefix.
    """

    def __init__(self, col_name):
        self.prefix = "nfs_ganesha"
        self.col_name = col_name

    def make_name(self, suffix):
        return self.prefix + "_" + self.col_name + "_" + suffix

    def make_gauge(self, sname, docs, labels=None):
        return prometheus_client.core.GaugeMetricFamily(
            self.make_name(sname), docs, labels=labels
        )


class ExportCollector(Collector):
    """ExportCollector implements Prometheus metrics collector for NFS-Ganesha.

    Converts NFS-Ganesha exports-stats information to Prometheus gauge metrics,
    for each NFS protocol version.
    """

    def __init__(self):
        Collector.__init__(self, "export")
        self.dbus_if = ganesha_dbus.RetrieveExportStats()

    def collect(self):
        yield from self.collect_global_stats()
        yield from self.collect_export_stats()

    def collect_global_stats(self):
        stats = self.dbus_if.global_stats()
        status = str(stats.status)
        success = bool(stats.success)
        total = 0
        gauge = self.make_gauge(
            "total_ops_nfsv3",
            "Total number of NFSv3 ops",
            labels=["status"],
        )
        total = int(stats.nfsv3_total) if success else 0
        gauge.add_metric([status], total)
        yield gauge

        gauge = self.make_gauge(
            "total_ops_nfsv40",
            "Total number of NFSv4.0 ops",
            labels=["status"],
        )
        total = int(stats.nfsv40_total) if success else 0
        gauge.add_metric([status], total)
        yield gauge

        gauge = self.make_gauge(
            "total_ops_nfsv41",
            "Total number of NFSv4.1 ops",
            labels=["status"],
        )
        total = int(stats.nfsv41_total) if success else 0
        gauge.add_metric([status], total)
        yield gauge

        gauge = self.make_gauge(
            "total_ops_nfsv42",
            "Total number of NFSv4.2 ops",
            labels=["status"],
        )
        total = int(stats.nfsv42_total) if success else 0
        gauge.add_metric([status], total)
        yield gauge

    def collect_export_stats(self):
        stats = self.dbus_if.export_stats()
        gauge = self.make_gauge(
            "count",
            "Number of active exports",
        )
        gauge.add_metric([], len(stats.exports))
        yield gauge


class ClientCollector(Collector):
    """ClientCollector implements Prometheus metrics collector for NFS-Ganesha.

    Converts NFS-Ganesha clients-stats information to Prometheus gauge metrics,
    for each NFS protocol version.
    """

    def __init__(self):
        Collector.__init__(self, "client")
        self.dbus_if = ganesha_dbus.RetrieveClientStats()

    def collect(self):
        yield from self.collect_io_ops_stats()

    def collect_io_ops_stats(self):
        clients = self.dbus_if.list_clients()
        for client in self.get_clients1(clients):
            addr = client[0]
            iops_stats = self.dbus_if.client_io_ops_stats(addr)
            if iops_stats.status == "OK":
                yield from self.collect_io_ops_stats_of(addr, iops_stats)

    @staticmethod
    def get_clients1(obj):
        if hasattr(obj, "clients"):
            clients1 = obj.clients[1]  # nfs-ganesha-4
        else:
            clients1 = obj._clients[1]  # pylint: disable=protected-access
        return clients1

    # pylint: disable=too-many-arguments

    def add_gauge_metric(self, name, docs, addr, val):
        labels = ["addr"]
        labels_dat = [addr]
        gauge = self.make_gauge(name, docs, labels)
        gauge.add_metric(labels_dat, val)
        return gauge

    # pylint: disable=too-many-branches
    # pylint: disable=too-many-statements
    def collect_io_ops_stats_of(self, addr, iops_stats):
        protos = {0: "NFSv3", 1: "NFSv4.0", 2: "NFSv4.1", 3: "NFSv4.2"}
        cnt = 3
        for j in range(0, 4):
            if not iops_stats.stats[cnt]:
                cnt += 1
                continue
            i = 0
            proto = protos.get(j, "")
            prtag = self.protocol_tag(proto)
            while i < 4:
                idx = cnt + i + 1
                if i == 0:
                    val = iops_stats.stats[idx][0]
                    yield self.add_gauge_metric(
                        "io_ops_{}_read_total".format(prtag),
                        "{} READ total".format(proto),
                        addr,
                        val,
                    )
                    val = iops_stats.stats[idx][1]
                    yield self.add_gauge_metric(
                        "io_ops_{}_read_errors".format(prtag),
                        "{} READ errors".format(proto),
                        addr,
                        val,
                    )
                    val = iops_stats.stats[idx][2]
                    yield self.add_gauge_metric(
                        "io_ops_{}_read_transferred".format(prtag),
                        "{} READ transferred".format(proto),
                        addr,
                        val,
                    )
                if i == 1:
                    val = iops_stats.stats[idx][0]
                    yield self.add_gauge_metric(
                        "io_ops_{}_write_total".format(prtag),
                        "{} WRITE total".format(proto),
                        addr,
                        val,
                    )
                    val = iops_stats.stats[idx][1]
                    yield self.add_gauge_metric(
                        "io_ops_{}_write_errors".format(prtag),
                        "{} WRITE errors".format(proto),
                        addr,
                        val,
                    )
                    val = iops_stats.stats[idx][2]
                    yield self.add_gauge_metric(
                        "io_ops_{}_write_transferred".format(prtag),
                        "{} WRITE transferred".format(proto),
                        addr,
                        val,
                    )
                if i == 2:
                    val = iops_stats.stats[idx][0]
                    yield self.add_gauge_metric(
                        "io_ops_{}_other_total".format(prtag),
                        "{} other total".format(proto),
                        addr,
                        val,
                    )
                    val = iops_stats.stats[idx][1]
                    yield self.add_gauge_metric(
                        "io_ops_{}_other_errors".format(prtag),
                        "{} other errors".format(proto),
                        addr,
                        val,
                    )
                if i == 3:
                    pass
                if i == 2 and j < 2:
                    i += 1
                i += 1
            if j < 2:
                cnt += 4
            else:
                cnt += 5

    @staticmethod
    def protocol_tag(proto):
        return str(proto).lower().replace(".", "")

    @staticmethod
    def last_active_timestamp(st):
        return time.ctime(st.timestamp[0]) + str(st.timestamp[1])


class MetricsEndpoint:
    """MetricsEndpoint implemnts Prometheus metrics endpoint for NFS-Ganesha.

    Allows Prometheus to scrape NFS-Ganesha stats via HTTP as metrics and
    collect exports and clients stats. Communicates with NFS-ganesha via DBus
    interface. By default, listen on port 8080.
    """

    DEFAULT_PORT = 8080

    def __init__(self, port=DEFAULT_PORT):
        self.port = port
        self.registry = prometheus_client.core.REGISTRY
        self.export_col = ExportCollector()
        self.client_col = ClientCollector()

    def probe_ganesha(self):
        stats = self.export_col.dbus_if.global_stats()
        status = str(stats.status)
        success = bool(stats.success)
        return (success, status)

    def serve_http(self):
        self.registry.register(self.export_col)
        self.registry.register(self.client_col)
        prometheus_client.start_http_server(self.port)
        while True:
            time.sleep(1)


def goodbye(exit_code, msg=""):
    print(msg)
    time.sleep(1)
    sys.exit(exit_code)


def usage(exit_code):
    goodbye(exit_code, sys.argv[0] + " [--port=PORT]")


def parseargs():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "p:", ["port="])
    except getopt.GetoptError as err:
        print(err)
        usage(1)

    if len(args) > 0:
        usage(2)

    port = MetricsEndpoint.DEFAULT_PORT
    for o, a in opts:
        if o in ("-p", "--port"):
            port = int(a)
        else:
            usage(3)
    return port


def main():
    port = parseargs()
    metrics_endpoint = MetricsEndpoint(port)
    (ok, status) = metrics_endpoint.probe_ganesha()
    if not ok:
        goodbye(1, status)
    metrics_endpoint.serve_http()


if __name__ == "__main__":
    main()
