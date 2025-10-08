from logging import getLogger
from typing import Dict, List

# ignore flake line too long in imports
from api_app.analyzers_manager.models import AnalyzerReport
from api_app.visualizers_manager.classes import VisualizableObject, Visualizer
from api_app.visualizers_manager.decorators import (
    visualizable_error_handler_with_params,
)
from api_app.visualizers_manager.enums import VisualizableSize

logger = getLogger(__name__)


class UrlScan(Visualizer):
    @visualizable_error_handler_with_params()
    def _scan_page_item(
        self, analyzer_report: AnalyzerReport, key: str
    ) -> VisualizableObject:
        printable_analyzer_name = analyzer_report.config.name.replace("_", " ")
        logger.debug(f"{printable_analyzer_name=}: {key}")
        disable_element = False
        task = analyzer_report.report["page"]
        # return self.VList(
        #   name=self.Base(value=f"{key}", disable=True),
        #   value=[
        #       self.Base(
        #           value=task[key],
        #           disable=False,
        #       )
        #   ],
        #   size=self.Size.S_ALL,
        #   disable=disable_element,
        #   start_open=True,
        # )

        return self.Base(value=task[key], disable=False, size=VisualizableSize.S_ALL)

    @visualizable_error_handler_with_params()
    def _scan_task_item(
        self, analyzer_report: AnalyzerReport, key: str
    ) -> VisualizableObject:
        printable_analyzer_name = analyzer_report.config.name.replace("_", " ")
        logger.debug(f"{printable_analyzer_name=}: {key}")
        disable_element = False
        task = analyzer_report.report["task"]
        return self.VList(
            name=self.Base(value=f"{key}", disable=disable_element),
            value=[
                self.Base(
                    value=task[key],
                    disable=False,
                )
            ],
            size=self.Size.S_2,
            disable=disable_element,
            start_open=True,
        )

    def find_domain_ips(self, domain: str, report: AnalyzerReport) -> list[str]:
        "Retrieve a list of IPs observerd with a given IP based on the domain stats"

        if "://" in domain:
            domain = domain.split("://")[-1].split("/")[0]

        stats: list = report.report["stats"]["domainStats"]
        for stat in stats:
            if stat["domain"] == domain:
                return stat["ips"]
        return ["No IP matched"]

    def run(self) -> List[Dict]:
        try:
            url_scan_report: list[AnalyzerReport] = [
                self.get_analyzer_reports().get(config__name="UrlScan_Submit_Result")
            ]
        except AnalyzerReport.DoesNotExist:
            logger.warning("Couldn't access expecte URLScan report")
            return []
        # Tab
        report = url_scan_report[0]

        page = self.Page(name="URL Scan")

        # Line 1
        # Redirect chain
        page.add_level(
            self.Level(
                position=1,
                size=self.LevelSize.S_3,
                horizontal_list=self.HList(
                    value=[
                        self.Table(
                            [
                                self.TableColumn(a, disable_sort_by=True)
                                for a in ["url", "ip", "response code"]
                            ],
                            [
                                {
                                    "url": self.Base(
                                        report.report["data"]["requests"][0]["request"][
                                            "documentURL"
                                        ]
                                    ),
                                    "ip": self.HList(
                                        [
                                            self.Base(ip)
                                            for ip in self.find_domain_ips(
                                                report.report["data"]["requests"][0][
                                                    "request"
                                                ]["documentURL"],
                                                report,
                                            )
                                        ]
                                    ),
                                    "response code": self.Base(
                                        report.report["data"]["requests"][0][
                                            "response"
                                        ]["response"]["status"]
                                    ),
                                }
                            ]
                            + [
                                {
                                    "url": self.Base(
                                        redirect["redirectResponse"]["url"]
                                    ),
                                    "ip": self.HList(
                                        [
                                            self.Base(ip)
                                            for ip in self.find_domain_ips(
                                                redirect["redirectResponse"]["url"],
                                                report,
                                            )
                                        ]
                                    ),
                                    "response code": self.Base(
                                        redirect["redirectResponse"]["status"]
                                    ),
                                }
                                for redirect in report.report["data"]["requests"][0][
                                    "requests"
                                ]
                                if "redirectResponse" in redirect
                            ],
                            size=VisualizableSize.S_ALL,
                        )
                    ],
                ),
            )
        )
        page.add_level(
            self.Level(
                position=2,
                size=self.LevelSize.S_3,
                horizontal_list=self.HList(
                    value=[
                        self.Table(
                            [
                                self.TableColumn(a)
                                for a in ["domain", "asn", "ptr", "server", "asnname"]
                            ],
                            [
                                {
                                    "domain": self._scan_page_item(
                                        url_scan_report[0], "domin"
                                    ),
                                    "asn": self._scan_page_item(
                                        url_scan_report[0], "asn"
                                    ),
                                    "ptr": self._scan_page_item(
                                        url_scan_report[0], "ptr"
                                    ),
                                    "server": self._scan_page_item(
                                        url_scan_report[0], "server"
                                    ),
                                    "asnname": self._scan_page_item(
                                        url_scan_report[0], "asnname"
                                    ),
                                }
                            ],
                            size=VisualizableSize.S_ALL,
                        )
                    ]
                ),
            )
        )
        page.add_level(
            self.Level(
                position=3,
                size=self.LevelSize.S_3,
                horizontal_list=self.HList(
                    value=[
                        self._scan_task_item(url_scan_report[0], "domain"),
                        self._scan_task_item(url_scan_report[0], "reportURL"),
                        self._scan_task_item(url_scan_report[0], "screenshotURL"),
                    ]
                ),
            )
        )
        logger.debug(f"levels: {page.to_dict()}")
        return [page.to_dict()]

    @classmethod
    def _monkeypatch(cls):
        # from kombu import uuid

        # malicious detector services (1st level)

        #        for python_module in cls.first_level_analyzers:
        #            try:
        #                AnalyzerReport.objects.get(
        #                    config=AnalyzerConfig.objects.get(python_module=python_module),
        #                    job=Job.objects.first(),
        #                    status=AnalyzerReport.Status.SUCCESS,
        #                )
        #            except AnalyzerReport.DoesNotExist:
        #                report = AnalyzerReport(
        #                    config=AnalyzerConfig.objects.get(python_module=python_module),
        #                    job=Job.objects.first(),
        #                    status=AnalyzerReport.Status.SUCCESS,
        #                    report={
        #                        "observable": "dns.google.com",
        #                        "resolutions": [
        #                            {
        #                                "TTL": 456,
        #                                "data": "8.8.8.8",
        #                                "name": "dns.google.com",
        #                                "type": 1,
        #                            },
        #                            {
        #                                "TTL": 456,
        #                                "data": "8.8.4.4",
        #                                "name": "dns.google.com",
        #                                "type": 1,
        #                            },
        #                        ],
        #                    },
        #                    task_id=uuid(),
        #                    parameters={},
        #                )
        #                report.full_clean()
        #                report.save()
        #
        #        # classic DNS resolution (2nd level)
        #        for python_module in cls.second_level_analyzers:
        #            try:
        #                AnalyzerReport.objects.get(
        #                    config=AnalyzerConfig.objects.get(python_module=python_module),
        #                    job=Job.objects.first(),
        #                )
        #            except AnalyzerReport.DoesNotExist:
        #                report = AnalyzerReport(
        #                    config=AnalyzerConfig.objects.get(python_module=python_module),
        #                    job=Job.objects.first(),
        #                    status=AnalyzerReport.Status.SUCCESS,
        #                    report={"observable": "dns.google.com", "malicious": False},
        #                    task_id=uuid(),
        #                    parameters={},
        #                )
        #                report.full_clean()
        #                report.save()
        #
        #        patches = []
        #
        return super()._monkeypatch(patches=patches)
