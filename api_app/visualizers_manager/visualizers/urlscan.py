from logging import getLogger
from typing import Dict, List

# ignore flake line too long in imports
from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.choices import ObservableClassification
from api_app.models import Job
from api_app.visualizers_manager.classes import VisualizableObject, Visualizer
from api_app.visualizers_manager.decorators import (
    visualizable_error_handler_with_params,
)

logger = getLogger(__name__)


class UrlScan(Visualizer):
    @classmethod
    @property
    def first_level_analyzers(cls) -> List[str]:
        return [  # noqa
            ClassicDNSResolver.python_module,
            CloudFlareDNSResolver.python_module,
            GoogleDNSResolver.python_module,
            DNS0EUResolver.python_module,
            Quad9DNSResolver.python_module,
        ]

    @classmethod
    @property
    def second_level_analyzers(cls) -> List[str]:
        return [  # noqa
            CloudFlareMaliciousDetector.python_module,
            DNS0EUMaliciousDetector.python_module,
            Quad9MaliciousDetector.python_module,
        ]


    @visualizable_error_handler_with_params()
    def _scan_page_item(self, analyzer_report: AnalyzerReport, key: str) -> VisualizableObject:
        printable_analyzer_name = analyzer_report.config.name.replace("_", " ")
        logger.debug(f"{printable_analyzer_name=}: {key}")
        disable_element = False
        task = analyzer_report.report["page"]
        return self.VList(
            name=self.Base(value=f"{key}", disable=disable_element),
            value=[self.Base(
                    value=task[key],
                    disable=False,
                )
            ],
            size=self.Size.S_2,
            disable=disable_element,
            start_open=True,
        )
        
    @visualizable_error_handler_with_params()
    def _scan_task_item(self, analyzer_report: AnalyzerReport, key: str) -> VisualizableObject:
        printable_analyzer_name = analyzer_report.config.name.replace("_", " ")
        logger.debug(f"{printable_analyzer_name=}: {key}")
        disable_element = False
        task = analyzer_report.report["task"]
        return self.VList(
            name=self.Base(value=f"{key}", disable=disable_element),
            value=[self.Base(
                    value=task[key],
                    disable=False,
                )
            ],
            size=self.Size.S_2,
            disable=disable_element,
            start_open=True,
        )
    
    
    def run(self) -> List[Dict]:
        try:
            url_scan_report = [self.analyzer_reports().get(config__name='UrlScan_Submit_Result')]
        except AnalyzerReport.DoesNotExist:
            logger.warning("Couldn't access expecte URLScan report")
            return []
        # Tab        
        page = self.Page(name="URL Scan")
        # Line 1 
        page.add_level(
            self.Level(
                position=1,
                size=self.LevelSize.S_3,
                horizontal_list=self.HList(value=[self.Table(
                   ['url', 'ip'],
                   [
                       {'url': self._scan_page_item(url_scan_report[0], 'url'),
                       'ip': self._scan_page_item(url_scan_report[0], 'ip'),
                       }
                   ]
            )]
        )))
        page.add_level(
            self.Level(
                position=2,
                size=self.LevelSize.S_3,
                horizontal_list=self.HList(value=[self.Table(
                   ['domain', 'asn', 'ptr', 'server', 'asnname'],
                   [
                       {
                       'domain': self._scan_page_item(url_scan_report[0], 'domin'),
                       'asn': self._scan_page_item(url_scan_report[0], 'asn'),
                       'ptr': self._scan_page_item(url_scan_report[0], 'ptr'),
                       'server': self._scan_page_item(url_scan_report[0], 'server'),
                       'asnname': self._scan_page_item(url_scan_report[0], 'asnname')
                       }
                   ]
            )]
        )))
        page.add_level(
            self.Level(
                position=3,
                size=self.LevelSize.S_3,
                horizontal_list=self.HList(value=[
					self._scan_task_item(url_scan_report[0], 'domain'),
					self._scan_task_item(url_scan_report[0], 'reportURL'),
					self._scan_task_item(url_scan_report[0], 'screenshotURL'),
				]),
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
