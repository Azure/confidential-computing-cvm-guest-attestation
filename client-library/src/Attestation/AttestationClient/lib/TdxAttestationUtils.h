/**
 * @file TdxAttestationUtils.h
 * @author Javier Vega
 * @brief Utilities for getting TD Report using Intel's tdx-attest driver
 * @version 0.1
 * @date 2023-03-06
 *
 * @copyright Copyright (c) Microsoft Corporation.  All rights reserved. 2023
 *
 */

#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <sys/ioctl.h>
#include <stdio.h>

// Definitions copied from https://github.com/intel/SGXDataCenterAttestationPrimitives

/* Length of the REPORTDATA used in TDG.MR.REPORT TDCALL */
#define TDX_REPORTDATA_LEN 64

/* Length of TDREPORT used in TDG.MR.REPORT TDCALL */
#define TDX_REPORT_LEN 1024

/* TDX Device Driver path */
#define TDX_ATTEST_DEV_PATH "/dev/tdx_guest"

#define TDX_GET_REPORT_SUCCESS 0
#define TDX_GET_REPORT_FAILED -1

/**
 * struct tdx_report_req - Request struct for TDX_CMD_GET_REPORT IOCTL.
 *
 * @reportdata: User buffer with REPORTDATA to be included into TDREPORT.
 *              Typically it can be some nonce provided by attestation
 *              service, so the generated TDREPORT can be uniquely verified.
 * @tdreport: User buffer to store TDREPORT output from TDCALL[TDG.MR.REPORT].
 */
typedef struct TdxReportRequest_t {
    uint8_t reportdata[TDX_REPORTDATA_LEN]; // Hash of well formed JSON object
    uint8_t tdreport[TDX_REPORT_LEN];
} TdxReportRequest_t;


/*
 * TDX_CMD_GET_REPORT - Get TDREPORT using TDCALL[TDG.MR.REPORT]
 *
 * Return 0 on success, -EIO on TDCALL execution failure, and
 * standard errno on other general error cases.
 */
#define TDX_CMD_GET_REPORT _IOWR('T', 1, TdxReportRequest_t)

#define TD_REPORT_SIZE (1024)
#define TD_QUOTE_MAX_SIZE (8192)

/**
 * @brief Get TD Report using Intel's driver
 *
 * @param out_request_data
 * @return int
 */
int GetTdReport(char* out_request_data, unsigned char *report_data, size_t report_data_size) {
    TdxReportRequest_t report;
    if (out_request_data == NULL) {
        return TDX_GET_REPORT_FAILED;
    }

    if (report_data != NULL && report_data_size <= TDX_REPORTDATA_LEN) {
        memcpy(report.reportdata, report_data, report_data_size);
    }

    int device_fd = open(TDX_ATTEST_DEV_PATH, O_RDWR | O_SYNC);
    if (device_fd == -1) {
        return TDX_GET_REPORT_FAILED;
    }

    int return_code = ioctl(device_fd, TDX_CMD_GET_REPORT, &report);
    if (return_code != 0) {
        close(device_fd);
        return TDX_GET_REPORT_FAILED;
    }

    memcpy(out_request_data, report.tdreport, TDX_REPORT_LEN);

    return TDX_GET_REPORT_SUCCESS;
}