#!/usr/bin/env python3
# coding=utf-8


import psycopg2
import standardize
import tool
import time


class CrtSh:

    def __init__(self):
        self.name = "crt.sh"
        self.__db_host = "91.199.212.73"
        self.__db_name = "certwatch"
        self.__db_user = "guest"

    def connect(self):
        while True:
            try:
                self.conn = psycopg2.connect(database=self.__db_name, user=self.__db_user, host=self.__db_host)
                self.conn.set_session(readonly=True, autocommit=True)
            except Exception as e:
                tool.write_journal("crt.sh", e)
                continue
            try:
                self.cur = self.conn.cursor()
                return
            except Exception as e:
                tool.write_journal("crt.sh", e)
                self.conn.close()
                continue

    def disconnect(self):
        self.cur.close()
        self.conn.close()

    @staticmethod
    def __search_by_sn_sql(serial_number):
        sql = """
        SELECT DISTINCT
            x509_commonName(cai.CERTIFICATE) COMMON_NAME,
            x509_notBefore(cai.CERTIFICATE) NOT_BEFORE,
            x509_notAfter(cai.CERTIFICATE) NOT_AFTER,
            encode(x509_serialNumber(cai.CERTIFICATE), 'hex') SERIAL_NUMBER,
            encode(digest(cai.CERTIFICATE, 'sha256'), 'hex') SHA256,
            array_agg(DISTINCT concat(cl.NAME,': ',cle.ENTRY_TIMESTAMP)) LOG_LIST
        FROM 
            certificate_and_identities cai,
            ct_log_entry cle,
            ct_log cl
        WHERE 
            x509_serialNumber(cai.CERTIFICATE) = '{0}'
            AND cle.CERTIFICATE_ID = cai.CERTIFICATE_ID
            AND cl.ID = cle.CT_LOG_ID
        GROUP BY cai.CERTIFICATE;
        """.format(serial_number)
        return sql

    @staticmethod
    def __search_by_sha256_sql(sha256):
        sql = """
        SELECT DISTINCT
            x509_commonName(cai.CERTIFICATE) COMMON_NAME,
            x509_notBefore(cai.CERTIFICATE) NOT_BEFORE,
            x509_notAfter(cai.CERTIFICATE) NOT_AFTER,
            encode(x509_serialNumber(cai.CERTIFICATE), 'hex') SERIAL_NUMBER,
            encode(digest(cai.CERTIFICATE, 'sha256'), 'hex') SHA256,
            array_agg(DISTINCT concat(cl.NAME,': ',cle.ENTRY_TIMESTAMP)) LOG_LIST
        FROM 
            certificate_and_identities cai,
            ct_log_entry cle,
            ct_log cl
        WHERE 
            digest(cai.CERTIFICATE, 'sha256') = '{0}'
            AND cle.CERTIFICATE_ID = cai.CERTIFICATE_ID
            AND cl.ID = cle.CT_LOG_ID
        GROUP BY cai.CERTIFICATE;
        """.format(sha256)
        return sql

    @staticmethod
    def __search_by_domain_sql(domain):
        sql = """
        WITH ci AS (
            SELECT min(sub.CERTIFICATE_ID) ID,
                   min(sub.ISSUER_CA_ID) ISSUER_CA_ID,
                   array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES,
                   x509_commonName(sub.CERTIFICATE) COMMON_NAME,
                   x509_notBefore(sub.CERTIFICATE) NOT_BEFORE,
                   x509_notAfter(sub.CERTIFICATE) NOT_AFTER,
                   encode(digest(sub.CERTIFICATE, 'sha256'), 'hex') SHA256,
                   encode(x509_serialNumber(sub.CERTIFICATE), 'hex') SERIAL_NUMBER
                FROM (SELECT *
                          FROM certificate_and_identities cai
                          WHERE plainto_tsquery('certwatch', '{0}') @@ identities(cai.CERTIFICATE)
                              AND cai.NAME_VALUE ILIKE ('%' || '.{0}')
                              AND coalesce(x509_notAfter(cai.CERTIFICATE), 'infinity'::timestamp) >= date_trunc('year', now() AT TIME ZONE 'UTC')
                              AND x509_notAfter(cai.CERTIFICATE) >= now() AT TIME ZONE 'UTC'
                              AND NOT EXISTS (
                                  SELECT 1
                                      FROM certificate c2
                                      WHERE x509_serialNumber(c2.CERTIFICATE) = x509_serialNumber(cai.CERTIFICATE)
                                          AND c2.ISSUER_CA_ID = cai.ISSUER_CA_ID
                                          AND c2.ID < cai.CERTIFICATE_ID
                                          AND x509_tbscert_strip_ct_ext(c2.CERTIFICATE) = x509_tbscert_strip_ct_ext(cai.CERTIFICATE)
                                      LIMIT 1
                              )
                          LIMIT 10000
                     ) sub
                GROUP BY sub.CERTIFICATE
        )
        SELECT ci.ISSUER_CA_ID,
                ca.NAME ISSUER_NAME,
                ci.COMMON_NAME,
                array_to_string(ci.NAME_VALUES, chr(10)) NAME_VALUE,
                ci.ID ID,
                le.ENTRY_TIMESTAMP,
                ci.NOT_BEFORE,
                ci.NOT_AFTER,
                ci.SERIAL_NUMBER,
                ci.SHA256,
                le.LOG_LIST
            FROM ci
                    LEFT JOIN LATERAL (
                        SELECT min(ctle.ENTRY_TIMESTAMP) ENTRY_TIMESTAMP,
                               array_agg(DISTINCT concat(ctl.NAME,': ',ENTRY_TIMESTAMP)) LOG_LIST
                        FROM ct_log_entry ctle, ct_log ctl
                        WHERE ctle.CERTIFICATE_ID = ci.ID AND ctl.ID = ctle.CT_LOG_ID
                    ) le ON TRUE,
                 ca
            WHERE ci.ISSUER_CA_ID = ca.ID
            ORDER BY le.ENTRY_TIMESTAMP DESC NULLS LAST;
         """.format(domain)
        return sql

    @staticmethod
    def __serial_number(serial_number):
        serial_number = hex(int(serial_number))[2:]
        if len(serial_number) % 2 == 1:
            return "\\x0" + serial_number
        elif serial_number[0] in list("89abcdef"):
            return "\\x00" + serial_number
        else:
            return "\\x" + serial_number

    @staticmethod
    def __sha256(sha256):
        return "\\x" + sha256

    def search_by_sn(self, serial_number):
        serial_number = self.__serial_number(serial_number)
        sql = self.__search_by_sn_sql(serial_number)
        while True:
            try:
                self.cur.execute(sql)
            except Exception as e:
                tool.write_journal("crt.sh", e)
                self.disconnect()
                self.connect()
                continue
            else:
                break
        results = self.cur.fetchall()
        if not results:
            return ["Not Found!!!"]
        else:
            return results

    def search_by_sha256(self, sha256):
        sha256 = self.__sha256(sha256)
        sql = self.__search_by_sha256_sql(sha256)
        while True:
            try:
                self.cur.execute(sql)
            except Exception as e:
                tool.write_journal("crt.sh", e)
                self.disconnect()
                self.connect()
                continue
            else:
                break
        results = self.cur.fetchall()
        if not results:
            return ["Not Found!!!"]
        else:
            return results

    def search(self, domain):
        sql = self.__search_by_domain_sql(domain)
        raw_data_list = []
        while True:
            try:
                self.cur.execute(sql)
            except Exception as e:
                tool.write_journal("crt.sh", e)
                self.disconnect()
                self.connect()
                continue
            try:
                raw_data_list = self.cur.fetchall()
            except Exception as e:
                tool.write_journal("crt.sh", e)
                self.conn.commit()
                self.disconnect()
                self.connect()
                continue
            else:
                self.conn.commit()
                break
        return raw_data_list

    def standardize(self, raw_data_list, domain):
        cert_dict = dict()
        for cert in raw_data_list:
            standard_info = dict()
            standard_info["SHA256"] = [cert[9]]
            standard_info["SerialNumber"] = self.__sn(cert[8])
            standard_info["DomainInquired"] = domain
            standard_info["CommonName"] = cert[2]
            standard_info["DomainName"] = None
            standard_info["TargetDomain"] = self.__domains(cert[3])
            standard_info["NotBefore"] = self.__utc(cert[6])
            standard_info["NotAfter"] = self.__utc(cert[7])
            standard_info["Issuer"] = cert[1]
            standard_info["Log"] = self.__logs(cert[10])
            standard_info["Tag"] = None
            standard_info["LoggedFormat"] = None
            standard_info["LoggedTime"] = standardize.logged_time(standard_info["Log"])
            if len(standard_info["Log"]) == 1 and "comodododo" in standard_info["Log"]:
                continue
            fingerprint = standardize.fingerprint(standard_info)
            cert_dict[fingerprint] = standard_info
        return cert_dict

    @staticmethod
    def __domains(domains):
        return domains.split("\n")

    @staticmethod
    def __logs(logs):
        log_dict = {}
        for data in logs:
            log_name = data.split(': ')[0].lstrip('"').lower().replace(' ', '').replace('_', '').replace('\'', '')
            log_time = data.split(': ')[1].strip('"')
            try:
                log_time = log_time[:log_time.rindex('.')]
            except ValueError:
                pass
            log_dict[log_name] = tool.time_to_utc(log_time)
        return log_dict

    @staticmethod
    def __sn(serial_number):
        return str(int(serial_number, 16))

    @staticmethod
    def __utc(time_datetime):
        time_utc = tool.time_to_utc(str(time_datetime))
        return time_utc

    def processor(self, period, domain):
        file = tool.file_name(domain)
        self.connect()
        start_time = int(time.time())
        raw_data_list = self.search(domain)
        end_time = int(time.time())
        self.disconnect()
        tool.write_(tool.folder(period, self.name, tool.RAW_DATA_FOLDER) + file, raw_data_list, start_time, end_time)
        processed_data_list = self.standardize(raw_data_list, domain)
        tool.write_(tool.folder(period, self.name, tool.PROCESSED_CERT_FOLDER) + file, processed_data_list, start_time, end_time)

