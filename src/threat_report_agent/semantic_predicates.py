"""Conservative, shared API semantic predicates for static analysis.

API names are observations, not behaviour proof.  This module deliberately
uses normalized exact identities and narrowly defined families so that a
timing/environment query cannot become a process-execution signal merely
because the symbol contains a word such as ``system`` or ``process``.
"""

from __future__ import annotations

import re
from enum import StrEnum


class ApiSemantic(StrEnum):
    PROCESS_CREATION = "PROCESS_CREATION"
    COMMAND_EXECUTION = "COMMAND_EXECUTION"
    NETWORK_TRANSPORT = "NETWORK_TRANSPORT"
    DYNAMIC_LOADING = "DYNAMIC_LOADING"
    MEMORY_PROTECTION = "MEMORY_PROTECTION"
    REGISTRY_WRITE = "REGISTRY_WRITE"
    SERVICE_CONTROL = "SERVICE_CONTROL"
    SCHEDULED_TASK = "SCHEDULED_TASK"
    CRYPTO_DECODE = "CRYPTO_DECODE"
    ENVIRONMENT_QUERY = "ENVIRONMENT_QUERY"
    TIMING_QUERY = "TIMING_QUERY"
    THREAD_SYNC = "THREAD_SYNC"
    MEMORY_ALLOCATION = "MEMORY_ALLOCATION"
    FILE_IO = "FILE_IO"
    GENERIC_RUNTIME = "GENERIC_RUNTIME"


def normalize_api_symbol(symbol: object) -> str:
    """Normalize common import/decompiler decoration without fuzzy matching."""
    value = str(symbol or "").strip().casefold()
    value = value.rsplit("!", 1)[-1]
    value = value.rsplit(".", 1)[-1]
    value = re.sub(r"^(?:__imp_|imp_|j_|thunk_|stub_|ptr_|pointer_)+", "", value)
    # Ghidra names import-pointer symbols as PTR_<API>_<address>.  The
    # address is a locator, not part of the API identity; removing only a
    # hexadecimal suffix keeps the normalization exact and avoids fuzzy
    # matching arbitrary symbol text.
    value = re.sub(r"_(?:0x)?[0-9a-f]{6,}$", "", value)
    value = value.lstrip("_")
    value = re.sub(r"@[0-9]+$", "", value)
    return value


_PROCESS_CREATION = {
    "createprocessa", "createprocessw", "createprocessasusera",
    "createprocessasuserw", "createprocesswithtokenw", "createprocesswithlogonw",
}
_COMMAND_EXECUTION = {
    "winexec", "shellexecutea", "shellexecutew", "shellexecuteex",
    "system", "popen", "execve", "execvp", "execl", "execlp", "spawnl",
}
_NETWORK_EXACT = {
    "socket", "connect", "wsaconnect", "getaddrinfo", "gethostbyname",
    "dnsquerya", "dnsqueryw", "internetopen", "internetopena", "internetopenw",
    "httpsendrequesta", "httpsendrequestw", "httpopenrequesta", "httpopenrequestw",
    "winhttpopen", "winhttpsendrequest", "winhttpreceiveresponse", "urlmon",
    "urldownloadtofilea", "urldownloadtofilew",
}
_DYNAMIC_LOADING = {
    "getprocaddress", "ldrgetprocedureaddress", "ldrloaddll", "loadlibrarya",
    "loadlibraryw", "loadlibraryex a", "loadlibraryexa", "loadlibraryexw",
    "getmodulehandlea", "getmodulehandlew",
    "freelibrary",
}
_INJECTION = {
    "openprocess", "writeprocessmemory", "createremotethread", "ntmapviewofsection",
    "queueuserapc", "setthreadcontext", "updatethreadcontext", "updateprocthreadattribute",
    "initializeprocthreadattributelist",
}
_MEMORY_PROTECTION = {"virtualprotect", "virtualprotectex", "ntprotectvirtualmemory"}
_MEMORY_ALLOCATION = {
    "virtualalloc", "virtualallocex", "heapalloc", "heaprealloc", "malloc",
    "calloc", "realloc", "free", "heapfree",
}
_TIMING_QUERY = {
    "getsystemtime", "getsystemtimeasfiletime", "systemtimetofiletime",
    "queryperformancecounter", "gettickcount", "gettickcount64", "timegettime",
}
_ENVIRONMENT_QUERY = {
    "getcurrentprocessid", "getcurrentthreadid", "getprocessid", "getthreadid",
    "getsysteminfo", "getnative systeminfo", "getnativesysteminfo", "getcomputernamea",
    "getcomputernamew", "getenvironmentvariablea", "getenvironmentvariablew",
    "getmodulefilenamea", "getmodulefilenamew",
}
_ANTI_ANALYSIS = {
    "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
    "outputdebugstringa", "outputdebugstringw", "getconsolewindow", "virtualquery",
    "globalmemorystatusex", "checkremotedebuggerpresent",
}
_REGISTRY_WRITE = {"regsetvaluea", "regsetvaluew", "regcreatekeya", "regcreatekeyw"}
_SERVICE_CONTROL = {"createservicea", "createservicew", "openscmanagera", "openscmanagerw", "startservicea", "startservicew"}
_SCHEDULED_TASK = {"schtasks", "taskschd", "itaskservice", "registertaskdefinition"}
_FILE_IO = {
    "createfilea", "createfilew", "readfile", "writefile", "copyfilea", "copyfilew",
    "movefilea", "movefilew", "deletefilea", "deletefilew", "createpipe", "peeknamedpipe",
    "sethandleinformation",
}
_GENERIC_RUNTIME = {"memset", "memcpy", "memmove", "memcmp", "strlen", "strcpy", "strncpy"}


def _family(value: str, prefixes: tuple[str, ...]) -> bool:
    return any(value.startswith(prefix) for prefix in prefixes)


def classify_api_symbol(symbol: object) -> ApiSemantic | None:
    """Return the most specific taxonomy class for one normalized symbol."""
    value = normalize_api_symbol(symbol)
    if not value:
        return None
    if value in _PROCESS_CREATION:
        return ApiSemantic.PROCESS_CREATION
    if value in _COMMAND_EXECUTION:
        return ApiSemantic.COMMAND_EXECUTION
    if value in _TIMING_QUERY:
        return ApiSemantic.TIMING_QUERY
    if value in _ENVIRONMENT_QUERY:
        return ApiSemantic.ENVIRONMENT_QUERY
    if value in _ANTI_ANALYSIS:
        return ApiSemantic.ENVIRONMENT_QUERY
    if value in _DYNAMIC_LOADING or _family(value, ("loadlibrary", "ldrload", "getprocaddress")):
        return ApiSemantic.DYNAMIC_LOADING
    if value in _MEMORY_PROTECTION:
        return ApiSemantic.MEMORY_PROTECTION
    if value in _MEMORY_ALLOCATION:
        return ApiSemantic.MEMORY_ALLOCATION
    if value in _REGISTRY_WRITE:
        return ApiSemantic.REGISTRY_WRITE
    if value in _SERVICE_CONTROL:
        return ApiSemantic.SERVICE_CONTROL
    if value in _SCHEDULED_TASK:
        return ApiSemantic.SCHEDULED_TASK
    if value in _FILE_IO or _family(value, ("createfile", "readfile", "writefile", "copyfile", "movefile", "deletefile")):
        return ApiSemantic.FILE_IO
    if value in _NETWORK_EXACT or _family(value, ("winhttp", "wininet", "internet", "httpopenrequest", "httpsendrequest", "urldownloadtofile", "wsasocket", "dnsquery")):
        return ApiSemantic.NETWORK_TRANSPORT
    if value in _GENERIC_RUNTIME:
        return ApiSemantic.GENERIC_RUNTIME
    return None


def is_process_creation_call(symbol: object) -> bool:
    return classify_api_symbol(symbol) is ApiSemantic.PROCESS_CREATION


def is_command_execution_call(symbol: object) -> bool:
    return classify_api_symbol(symbol) is ApiSemantic.COMMAND_EXECUTION


def is_network_transport_call(symbol: object) -> bool:
    return classify_api_symbol(symbol) is ApiSemantic.NETWORK_TRANSPORT


def is_dynamic_loader_call(symbol: object) -> bool:
    return classify_api_symbol(symbol) is ApiSemantic.DYNAMIC_LOADING


def is_injection_call(symbol: object) -> bool:
    return normalize_api_symbol(symbol) in _INJECTION


def is_anti_analysis_signal(symbol: object) -> bool:
    return normalize_api_symbol(symbol) in _ANTI_ANALYSIS


def is_execution_call(symbol: object) -> bool:
    return is_process_creation_call(symbol) or is_command_execution_call(symbol)


def semantic_category(symbol: object) -> str | None:
    """Map taxonomy to the compact categories used by static chains."""
    category = classify_api_symbol(symbol)
    return {
        ApiSemantic.PROCESS_CREATION: "execution",
        ApiSemantic.COMMAND_EXECUTION: "execution",
        ApiSemantic.NETWORK_TRANSPORT: "network",
        ApiSemantic.DYNAMIC_LOADING: "dynamic_resolution",
        ApiSemantic.MEMORY_PROTECTION: "loader",
        ApiSemantic.MEMORY_ALLOCATION: "loader",
        ApiSemantic.REGISTRY_WRITE: "persistence",
        ApiSemantic.SERVICE_CONTROL: "persistence",
        ApiSemantic.SCHEDULED_TASK: "persistence",
        ApiSemantic.FILE_IO: "file_io",
        ApiSemantic.TIMING_QUERY: "timing_query",
        ApiSemantic.ENVIRONMENT_QUERY: "environment_query",
        ApiSemantic.GENERIC_RUNTIME: "generic_runtime",
    }.get(category)


__all__ = [
    "ApiSemantic", "classify_api_symbol", "is_process_creation_call",
    "is_command_execution_call", "is_network_transport_call",
    "is_dynamic_loader_call", "is_anti_analysis_signal", "is_execution_call",
    "is_injection_call", "normalize_api_symbol", "semantic_category",
]
