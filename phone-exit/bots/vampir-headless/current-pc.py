"""Explicit read-only observation for the local account console; no identities."""
from dataclasses import asdict
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'vampir-shared'))
from vampir_core.bot_device_settings import validate, metadata_values


def collect_hardware():
    script = """$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$computer=Get-CimInstance Win32_ComputerSystem
$os=Get-CimInstance Win32_OperatingSystem
$gpu=@(Get-CimInstance Win32_VideoController | ForEach-Object { $_.Name })
@{manufacturer=$computer.Manufacturer;model=$computer.Model;memory_bytes=$computer.TotalPhysicalMemory;
  gpu=$gpu;os_caption=$os.Caption;os_version=$os.Version;timezone=(Get-TimeZone).Id;
  locale=(Get-Culture).Name} | ConvertTo-Json -Compress -Depth 3
"""
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
        capture_output=True, timeout=20, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode or len(result.stdout) > 16384:
        raise RuntimeError('Не удалось прочитать характеристики Windows через CIM.')
    value = json.loads(result.stdout.decode('utf-8-sig'))
    if type(value) is not dict:
        raise ValueError('Неизвестный ответ CIM.')
    return value


def observation(*, _system=None, _hardware=None):
    unknown = []
    settings = {}
    if _system is None:
        spec = importlib.util.spec_from_file_location('console_windows_inputs', HERE / 'windows-system-inputs.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _system = module.observe_inputs
    try:
        cpu, windows = _system()
        settings['cpu'] = asdict(cpu)
        if windows is not None:
            settings['windows'] = asdict(windows)
        else:
            unknown.append('Версия для SDK: GetVersionExW не вернул данные.')
    except (OSError, ValueError, RuntimeError, KeyError):
        unknown.append('CPU / версия SDK: проверенный системный reader недоступен.')
    try:
        hardware = (_hardware or collect_hardware)()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        hardware = {}
        unknown.append('Модель, память и видеокарта: CIM недоступен.')
    def text(key):
        value = hardware.get(key, '')
        return value.strip() if type(value) is str and len(value) <= 256 else ''
    metadata = {}
    generic = {'to be filled by o.e.m.', 'system manufacturer', 'system product name', 'default string'}
    model = ' '.join(value for value in (text('manufacturer'), text('model')) if value and value.lower() not in generic)
    if model:
        metadata['I_DeviceModel'] = model[:256]
    elif text('manufacturer') or text('model'):
        unknown.append('Производитель и модель в прошивке ПК не заполнены.')
    memory = hardware.get('memory_bytes')
    if type(memory) is int and 0 < memory < 2**64:
        metadata['I_NMRAM'] = format(memory / 2**30, '.2f') + ' GiB'
    gpu = hardware.get('gpu', [])
    if type(gpu) is list and all(type(item) is str and len(item) <= 256 for item in gpu):
        names = list(dict.fromkeys(item.strip() for item in gpu if item.strip()))
        if names:
            metadata['I_NMVGA'] = ' / '.join(names)[:256]
    for field, key in (('I_TimeZone', 'timezone'), ('I_LanguageCD', 'locale')):
        if text(key):
            metadata[field] = text(key)
    # An unsupported observed string is omitted, never replaced with an invented model.
    for field, value in list(metadata.items()):
        try:
            validate(dict(metadata={field: value}))
        except ValueError:
            del metadata[field]
            unknown.append(field + ': значение не подходит для текущего формата metadata.')
    if metadata:
        settings['metadata'] = metadata
    settings = validate(settings)
    return dict(observed_utc=datetime.now(timezone.utc).isoformat(), device_settings=settings,
        display_metadata=metadata_values(settings), unknown=unknown,
        os_display=' '.join(filter(None, (text('os_caption'), text('os_version')))),
        source='CPU: CPUID с проверкой DLL; версия SDK: GetVersionExW; оборудование: Windows CIM.',
        limits='Формат дополнительных metadata и принятие сервером не подтверждены. Ключи устройства не копируются.')
