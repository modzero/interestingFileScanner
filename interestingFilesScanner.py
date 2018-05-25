#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
    Interesting File Scanner extension for the Burp Suite Proxy
    Adds various scans for interesting files and directories
    Copyright (C) 2018 mezdanak

Created on Feb 2018-04-18
@author: mezdanak, @mezdanak, modzero AG, https://www.modzero.ch, @mod0

Contributes to:
@floyd_ch, @mod0, @hanno, @albinowax
'''
try:
    from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab

    from javax.swing import GroupLayout, JPanel, JCheckBox, JLabel

    import re
    import random
    import string
except ImportError:
    print 'Failed to load dependencies. This issue may be caused by using the unstable Jython 2.7 beta.'

VERSION = '1.0.1'
PATTERN_MAIN = {'/lfm.php': ['Lazy File Manager'], '/.idea/WebServers.xml': ['WebServers'],
                '/config/databases.yml': ['class:', 'param'], '/config/database.yml': ['adapter:', 'database:'],
                '/.git/config': ['[core]'], '/server-status': ['Apache Status'], '/sftp-config.json': ['type',
                                                                                                       'ftp'],
                '/WS_FTP.ini': ['[_config_]'], '/ws_ftp.ini': ['[_config_]'], '/WS_FTP.INI': ['[_config_]'],
                '/filezilla.xml': ['<FileZilla'], '/sitemanager.xml': ['<FileZilla'],
                '/FileZilla.xml': ['<FileZilla'],
                '/winscp.ini': ['[Configuration]'], '/WinSCP.ini': ['[Configuration]'],
                '/DEADJOE': ['in JOE when it aborted'],
                '/sites/default/private/files/backup_migrate/scheduled/test.txt': [
                    'this file should not be publicly accessible'],
                '/app/etc/local.xml': ['<config', 'Mage'], '/.env': ['APP_ENV=']}
SSH_KEYS = ['/id_rsa', '/id_dsa', '/.ssh/id_rsa', '/.ssh/id_dsa']
PRIVATE_KEYS = ['/server.key', '/privatekey.key', '/myserver.key', '/key.pem', 'placeholder_one',
                'placeholder_two']
PHP_FILES = ['index.php', 'wp-config.php', 'configuration.php', 'config.php', 'config.inc.php', 'settings.php']
SQL_FILES = ['/dump.sql', '/database.sql', '/1.sql', '/backup.sql', '/data.sql', '/db_backup.sql',
             '/dbdump.sql', '/db.sql', '/localhost.sql', '/mysql.sql', '/site.sql', '/sql.sql', '/temp.sql',
             '/users.sql', '/translate.sql', '/mysqldump.sql']

helpers = None
callbacks = None
checkbox_perHost = None
checkbox_common = None
checkbox_ssh = None
checkbox_key = None
checkbox_php = None
checkbox_sql = None


def safe_bytes_to_string(input_bytes):
    if input_bytes is None:
        input_bytes = ''
    return helpers.bytesToString(input_bytes)


def random_string():
    return "".join(random.choice(string.ascii_lowercase) for _ in range(12))


def is_same_issue(existingIssue, newIssue):
    if existingIssue.getIssueName() == newIssue.getIssueName():
        return -1
    else:
        return 0


class BurpExtender(IBurpExtender, IScannerCheck, ITab):
    def registerExtenderCallbacks(self, this_callbacks):
        global callbacks, helpers, checkbox_perHost, checkbox_common, checkbox_ssh, checkbox_key, checkbox_php, checkbox_sql
        callbacks = this_callbacks

        ui_label = JLabel('Scans to perform:')
        checkbox_perHost = self.defineCheckBox('Scan once per domain (web root only, not every subdirectory)')
        checkbox_common = self.defineCheckBox('Interesting files')
        checkbox_ssh = self.defineCheckBox('SSH private keys')
        checkbox_key = self.defineCheckBox('.key files')
        checkbox_php = self.defineCheckBox('PHP file scans')
        checkbox_sql = self.defineCheckBox('SQL file scans')

        self.tab = JPanel()
        layout = GroupLayout(self.tab)
        self.tab.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)

        layout.setHorizontalGroup(
            layout.createSequentialGroup()
                .addComponent(ui_label)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                          .addComponent(checkbox_common)
                          .addComponent(checkbox_ssh)
                          .addComponent(checkbox_key)
                          .addComponent(checkbox_php)
                          .addComponent(checkbox_sql))
                .addComponent(checkbox_perHost)
        )
        layout.setVerticalGroup(
            layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                          .addComponent(ui_label)
                          .addComponent(checkbox_common)
                          .addComponent(checkbox_perHost))
                .addComponent(checkbox_ssh)
                .addComponent(checkbox_key)
                .addComponent(checkbox_php)
                .addComponent(checkbox_sql)
        )

        helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Interesting Files Scanner")
        callbacks.registerScannerCheck(FileScanner())
        callbacks.addSuiteTab(self)

        print 'Interesting Files Scanner by @mezdanak v' + VERSION

        return

    def defineCheckBox(self, caption, selected=True, enabled=True):
        checkBox = JCheckBox(caption)
        checkBox.setSelected(selected)
        checkBox.setEnabled(enabled)
        return checkBox

    def getTabCaption(self):
        return "Interesting Files Scanner"

    def getUiComponent(self):
        return self.tab


class FileScanner(IScannerCheck):
    scanned_hosts = set()
    scanned_paths = set()

    def doPassiveScan(self, basePair):
        return []

    def check_404(self, basePair):
        attack = self.fetchURL(basePair, '/' + random_string() + ".htm")
        request_info = helpers.analyzeResponse(attack.getResponse())
        what_404 = {'state': (request_info.getStatusCode() == 200),
                    'content': safe_bytes_to_string(attack.getResponse())}
        if any(m in what_404['content'] for m in ['<?php', '<?=']):
            what_404['php'] = True
        else:
            what_404['php'] = False
        if 'INSERT INTO' in what_404['content']:
            what_404['sql'] = True
        else:
            what_404['sql'] = False
        return what_404

    def fetchURL(self, basePair, url):
        path = helpers.analyzeRequest(basePair).getUrl().getPath()
        if checkbox_perHost.isSelected():
            newReq = safe_bytes_to_string(basePair.getRequest()).replace(path, url, 1)
        else:
            if path[len(path) - 1:] != '/':
                newPath = path[:path.rfind('/')] + '/'
                newReq = safe_bytes_to_string(basePair.getRequest()).replace(path, newPath[:-1] + url, 1)
            else:
                newReq = safe_bytes_to_string(basePair.getRequest()).replace(path, path[:-1] + url, 1)
        return callbacks.makeHttpRequest(basePair.getHttpService(), newReq)

    def doActiveScan(self, basePair, insertionPoint):
        if checkbox_perHost.isSelected():
            host = basePair.getHttpService().getProtocol() + basePair.getHttpService().getHost() + \
                   ":" + str(basePair.getHttpService().getPort())
            if host in self.scanned_hosts:
                return []
            self.scanned_hosts.add(host)
        else:
            host_path = basePair.getHttpService().getProtocol() + basePair.getHttpService().getHost() + \
                        ":" + str(basePair.getHttpService().getPort()) + \
                        helpers.analyzeRequest(basePair).getUrl().getPath()
            if host_path[-1] != '/':
                host_path = host_path[:host_path.rfind('/')] + '/'
            if host_path in self.scanned_paths:
                return []
            self.scanned_paths.add(host_path)

        issues = []
        if checkbox_common.isSelected():
            issues.extend(self.interestingFileScan(basePair))
        if checkbox_ssh.isSelected():
            issues.extend(self.sshKeyFileScan(basePair))
        if checkbox_key.isSelected():
            issues.extend(self.privateKeyFileScan(basePair))
        if checkbox_php.isSelected():
            issues.extend(self.phpFileScan(basePair))
        if checkbox_sql.isSelected():
            issues.extend(self.phpFileScan(basePair))
        return issues

    def interestingFileScan(self, basePair):
        issues = []

        for url, expect in PATTERN_MAIN.items():
            attack = self.fetchURL(basePair, url)
            if len(expect) > 1:
                if (expect[0] in safe_bytes_to_string(attack.getResponse()) and
                            expect[1] in safe_bytes_to_string(attack.getResponse())):
                    # Check for false positive
                    baseline = self.fetchURL(basePair, url[:-1])
                    if (expect[0] not in safe_bytes_to_string(baseline.getResponse()) and
                                expect[1] not in safe_bytes_to_string(baseline.getResponse())):
                        issues.append(CustomScanIssue(
                            basePair.getHttpService(),
                            helpers.analyzeRequest(attack).getUrl(),
                            [attack, baseline],
                            url + " discovered",
                            "Sensitive directory or file likely leaked",
                            "High"))
            else:
                if expect[0] in safe_bytes_to_string(attack.getResponse()):
                    # Check for false positive
                    baseline = self.fetchURL(basePair, url[:-1])
                    if expect[0] not in safe_bytes_to_string(baseline.getResponse()):
                        issues.append(CustomScanIssue(
                            basePair.getHttpService(),
                            helpers.analyzeRequest(attack).getUrl(),
                            [attack, baseline],
                            url + " discovered",
                            "Sensitive directory or file likely leaked",
                            "High"))

        url = '/CVS/Root'
        attack = self.fetchURL(basePair, url)
        if (len(safe_bytes_to_string(attack.getResponse()).split("\n")) == 2
            and ':' in safe_bytes_to_string(attack.getResponse())
            and '<' not in safe_bytes_to_string(attack.getResponse())):
            issues.append(CustomScanIssue(
                basePair.getHttpService(),
                helpers.analyzeRequest(attack).getUrl(),
                [attack],
                url + " discovered",
                "Sensitive directory or file likely leaked",
                "High"))

        url = '/wallet.dat'
        attack = self.fetchURL(basePair, url)
        result_string = safe_bytes_to_string(attack.getResponse())
        if result_string[12:] == b'b1\x05\x00':
            issues.append(CustomScanIssue(
                basePair.getHttpService(),
                helpers.analyzeRequest(attack).getUrl(),
                [attack],
                url + " discovered",
                "bitcoin_wallet discovered",
                "High"))

        url = '/.svn/entries'
        attack = self.fetchURL(basePair, url)
        result_string = safe_bytes_to_string(attack.getResponse())
        try:
            if str(int(result_string)) + '\n' == result_string:
                issues.append(CustomScanIssue(
                    basePair.getHttpService(),
                    helpers.analyzeRequest(attack).getUrl(),
                    [attack],
                    url + " discovered",
                    "svn_dir discovered",
                    "High"))
        except ValueError:
            pass

        url = '/core'
        attack = self.fetchURL(basePair, url)
        result_string = safe_bytes_to_string(attack.getResponse())
        if result_string[0:4] == b'\x7fELF':
            issues.append(CustomScanIssue(
                basePair.getHttpService(),
                helpers.analyzeRequest(attack).getUrl(),
                [attack],
                url + " discovered",
                "coredump discovered",
                "High"))

        url = '/.DS_Store'
        attack = self.fetchURL(basePair, url)
        result_string = safe_bytes_to_string(attack.getResponse())
        if result_string[0:8] == b'\x00\x00\x00\x01Bud1':
            issues.append(CustomScanIssue(
                basePair.getHttpService(),
                helpers.analyzeRequest(attack).getUrl(),
                [attack],
                url + " discovered",
                "ds_store discovered",
                "High"))

        url = ['/cgi-bin/cgiecho', '/cgi-sys/cgiecho']
        for ck in url:
            attack = self.fetchURL(basePair, ck + '/' + random_string())
            if attack.getStatusCode() == 500:
                if '<P><EM>cgiemail' in safe_bytes_to_string(attack.getResponse()):
                    issues.append(CustomScanIssue(
                        basePair.getHttpService(),
                        helpers.analyzeRequest(attack).getUrl(),
                        [attack],
                        ck + " discovered",
                        "cgiecho discovered",
                        "High"))

        url = ['/CHANGELOG.txt', '/misc/drupal.js']
        for ck in url:
            attack = self.fetchURL(basePair, ck)
            if 'Drupal' in safe_bytes_to_string(attack.getResponse()):
                issues.append(CustomScanIssue(
                    basePair.getHttpService(),
                    helpers.analyzeRequest(attack).getUrl(),
                    [attack],
                    ck + " discovered",
                    """Drupal file discovered if version < 8.5.1, likely vulnerable for CVE-2018-7600 
                    Drupalgeddon2 Remote Code Execution""",
                    "High"))

        return issues

    def sshKeyFileScan(self, basePair):
        issues = []
        for url in SSH_KEYS:
            attack = self.fetchURL(basePair, url)
            for ps in ['BEGIN PRIVATE KEY', 'BEGIN RSA PRIVATE KEY', 'BEGIN DSA PRIVATE KEY']:
                if ps in safe_bytes_to_string(attack.getResponse()):
                    # Check for false positive
                    baseline = self.fetchURL(basePair, url[:-1])
                    if ps not in safe_bytes_to_string(baseline.getResponse()):
                        issues.append(CustomScanIssue(
                            basePair.getHttpService(),
                            helpers.analyzeRequest(attack).getUrl(),
                            [attack, baseline],
                            url + " discovered",
                            "Private Server Key leaked",
                            "High"))
        return issues

    def privateKeyFileScan(self, basePair):
        issues = []
        for url in PRIVATE_KEYS:
            if url == 'placeholder_one':
                host_key = re.sub('^www.', '', re.sub('(.*//|/.*)', "", basePair.getHttpService().getHost())) + ".key"
                url = '/' + host_key
            elif url == 'placeholder_two':
                host_key = re.sub('^www.', '', re.sub('(.*//|/.*)', "", basePair.getHttpService().getHost())) + ".key"
                www_key = 'www.' + host_key
                url = '/' + www_key
            attack = self.fetchURL(basePair, url)
            for ps in ['BEGIN PRIVATE KEY', 'BEGIN RSA PRIVATE KEY', 'BEGIN DSA PRIVATE KEY', 'BEGIN EC PRIVATE KEY']:
                if ps in safe_bytes_to_string(attack.getResponse()):
                    # Check for false positive
                    baseline = self.fetchURL(basePair, url[:-1])
                    if ps not in safe_bytes_to_string(baseline.getResponse()):
                        issues.append(CustomScanIssue(
                            basePair.getHttpService(),
                            helpers.analyzeRequest(attack).getUrl(),
                            [attack, baseline],
                            url + " discovered",
                            "Private Server Key leaked",
                            "High"))
        return issues

    def phpFileScan(self, basePair):
        issues = []
        what_404 = self.check_404(basePair)
        if not what_404:
            pass
        if what_404['php'] and not what_404['state']:
            pass
        else:
            for url in PHP_FILES:
                for ps in ['/_FILE_.bak', '/_FILE_~', '/._FILE_.swp', '/%23_FILE_%23']:
                    backup_file_url = ps.replace('_FILE_', url)
                    attack = self.fetchURL(basePair, backup_file_url)
                    if any(m in safe_bytes_to_string(attack.getResponse()) for m in ['<?php', '<?=']):
                        issues.append(CustomScanIssue(
                            basePair.getHttpService(),
                            helpers.analyzeRequest(attack).getUrl(),
                            [attack],
                            backup_file_url + " discovered",
                            "PHP backup file found",
                            "High"))
        return issues

    def sqlFileScan(self, basePair):
        issues = []
        what_404 = self.check_404(basePair)
        if not what_404['sql'] or what_404['state']:
            for url in SQL_FILES:
                attack = self.fetchURL(basePair, url)
                if any(m in safe_bytes_to_string(attack.getResponse()) for m in ['INSERT INTO']):
                    issues.append(CustomScanIssue(
                        basePair.getHttpService(),
                        helpers.analyzeRequest(attack).getUrl(),
                        [attack],
                        url + " discovered",
                        "sql_dump file discovered",
                        "High"))
            for ck in ['.gz', '.bz2', '.xz']:
                attack = self.fetchURL(basePair, url + ck)
                if any(m in safe_bytes_to_string(attack.getResponse()) for m
                       in [b'\x1f\x8b\x08', b'\xFD7zXZ\x00', b'BZh', b'BZ0']):
                    issues.append(CustomScanIssue(
                        basePair.getHttpService(),
                        helpers.analyzeRequest(attack).getUrl(),
                        [attack],
                        url + " discovered",
                        "sql_dump ~_gz,~_bz or ~_xz file discovered",
                        "High"))
        return issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return is_same_issue(existingIssue, newIssue)


class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
