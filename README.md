# Red Team vs EDR: техники и как их ловить

Разбор типичных приёмов обхода EDR и что смотреть в логах и SIEM, чтобы это не проходило мимо. Без готового кода — только механика, идеи и детекция. Написано так, чтобы можно было и понять что происходит, и сразу применить в правилах.

---

## Unhooking userland (ntdll и не только)

**Что происходит по шагам.** EDR в userland ставит хуки на функции ntdll — чаще всего на NtCreateThreadEx, NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory, реже на NtOpenProcess и т.д. При вызове управление уходит в код EDR, тот логирует и передаёт дальше. Красная команда не хочет светиться в этих логах. Варианты: (1) прочитать оригинальные байты ntdll с диска и перезаписать захуканный участок в своей копии в памяти; (2) замапить чистую ntdll из файла как отдельную секцию и вызывать из неё; (3) скопировать ntdll из другого процесса (например через NtReadVirtualMemory), куда EDR ещё не навесил хуки. В итоге вызовы идут в syscall минуя хуки.

**Что видно в телеметрии.** Загрузка ntdll.dll из пути, отличного от C:\Windows\System32 (или SysWOW64 для 32-бит). Маппинг файла ntdll в процесс — создание секции из файла и маппинг в адресное пространство. Изменение защиты страниц ntdll в своём процессе: сначала VirtualProtect на PAGE_EXECUTE_READWRITE, потом запись в область, потом обратно. Чтение памяти другого процесса (NtReadVirtualMemory / ReadProcessMemory) — особенно если читают область, где лежит ntdll. Открытие хендла на чужой процесс с правами VM_READ и последующее чтение — классическая связка перед unhook или перед копированием шеллкода.

**Где искать в EDR/SIEM.** События загрузки модулей: поле типа ModuleLoaded или LoadedImage, путь к файлу модуля. Если путь к ntdll не системный — уже кандидат. События изменения памяти процесса: изменение protection региона, запись в исполняемую область. События cross-process: OpenProcess, ReadProcessMemory (или их ntdll-обёртки). Корреляция: один процесс за короткое время (минута-две) делает remote read, потом в нём же аллочится RWX или меняется protection страниц, потом выполнение из региона без файлового бэкинга. Это не гарантия unhook, но паттерн очень подозрительный.

**Пример логики правила.** Триггер: процесс A открывает процесс B с VM_READ; в течение 60 секунд процесс A создаёт регион с PAGE_EXECUTE_READWRITE или выполняет код из региона без маппированного файла. Исключения: легитимные дебаггеры, мониторы производительности (если они в whitelist по пути). Дополнительно можно резать по родителю: если процесс A порождён от office, браузера или чего-то с сети — приоритет выше.

**Запрос (концепт под типичный SIEM).** Ищем за последние 24 часа: event_id или type = process_access / memory_read / module_load. Группировка по process_guid или process_id. Фильтр: target process или source process — не системные (не System32). В том же process_guid ищем event = allocation с атрибутами executable или module load с path содержащим ntdll и не из System32. Окно между событиями до 120 секунд.

---

## Direct syscalls и indirect syscalls

**Что происходит.** Вместо вызова NtCreateThreadEx из ntdll код сам формирует syscall: кладёт номер в eax/rax, аргументы в регистры, выполняет syscall/sysenter. Хук в ntdll не вызывается, userland-часть EDR ничего не видит. Indirect syscall — переход в ntdll на одну инструкцию (syscall) и сразу возврат, чтобы в call stack была хоть одна «нормальная» рамка и часть EDR не паниковала. Детект в основном на стороне ядра или по аномалиям стека.

**Что видно в телеметрии.** Создание потока или процесса: событие есть, но в метаданных call stack либо пустой, либо без полной цепочки из ntdll. Например только два фрейма: твой модуль и syscall. Выполнение кода из региона памяти, у которого нет file backing — образ не привязан к загруженному exe/dll. EDR с kernel-драйвером может отдавать «syscall invoked from non-backed region» или «thread start with unusual stack». Процесс с малым набором загруженных модулей (один exe и пара системных dll), но при этом создаёт удалённые потоки или открывает хендлы на lsass — диссонанс между «скромным» образом и опасными действиями.

**Где искать.** События создания потока/процесса с полем call_stack или stack_trace. Фильтр: stack не содержит ntdll или содержит меньше N фреймов. События типа «executable memory» или «code execution» с атрибутом no_file_backing. Корреляция: процесс без подозрительных модулей по пути, но с инъекцией в другой процесс или с созданием потока в чужом процессе.

**Пример правила.** Алерт если process create или thread create и в событии (если EDR отдаёт) stack depth < 3 или модуль в стеке не из System32. Либо: выполнение из региона с file path = empty и размер региона больше 4KB. Исключения: известные легитимные инжекторы (например софт для разработки), по whitelist по пути и хешу.

**Запрос.** event_type IN (thread_create, process_create) AND (call_stack IS NULL OR call_stack NOT CONTAINS "ntdll"). Или: event = execution AND file_path = "" AND region_size > 4096, с группировкой по process.

---

## Parent process spoofing и подмена call stack

**Что происходит.** EDR и SIEM часто смотрят на родительский процесс: explorer → что-то значит «пользователь запустил», svchost → «сервис». Красная команда подменяет родителя через API (например NtCreateProcessEx с другим parent, или через цепочку вызовов) так, что в логе создание процесса висит на explorer.exe или на msoffice. Иногда подменяют и call stack — чтобы в стеке были «красивые» фреймы. Цель — пройти эвристики типа «процесс от нестандартного родителя».

**Что видно.** Несоответствие: по одному источнику (например, другой лог или другой EDR-датчик) процесс создан из сервиса или из процесса без прав пользователя, а в process create событии parent = explorer. Редкие пары parent–child: комбинация, которая в твоей среде почти не встречается. Классика: mshta → cmd, wscript → powershell, rundll32 → cmd, браузер → powershell -enc. Контекст: родитель — процесс с активными сетевыми соединениями (например воркер), а дочерний — интерактивная оболочка. По времени: массовое создание процессов от одного родителя за секунды — не типично для обычного пользователя.

**Где искать.** В каждом process create должны быть ParentImage, ParentProcessId, Image, CommandLine (или аналоги). Строишь статистику: какие пары (parent name, child name) бывают. Редкие пары — кандидаты. Отдельно правила на известные вредоносные цепочки: sigma уже есть под T1059, можно взять и доработать под свои имена и пути. Смотри также на ParentCommandLine: если родитель svchost, а command line родителя пустой или не похож на типичный сервис — возможно подмена.

**Пример правила.** Blacklist пар: (mshta, cmd), (wscript, powershell), (cscript, powershell), (winword, cmd), (excel, powershell). Плюс аномалия: новая пара (parent, child), которую за последние 30 дней ни разу не видели. Плюс: parent = процесс с сетевыми коннектами (данные из network events) и child = cmd или powershell.

**Запрос.** process_create WHERE (ParentImage, Image) IN список_плохих_пар. Или: process_create GROUP BY ParentImage, Image HAVING count < 2 за окно 30 дней — редкость. Объединение с network: JOIN по host/user и времени, фильтр по child = powershell.exe.

---

## AMSI bypass и отключение скриптовой телеметрии

**Что происходит.** AMSI (Antimalware Scan Interface) передаёт контент скриптов (PowerShell, VBScript и т.д.) в AV/EDR перед выполнением. Обход: патч AmsiScanBuffer в памяти (замена на ret или на возврат AMSI_RESULT_CLEAN), либо загрузка своего контекста через ReflectiveLoading, либо подмена .NET Assembly.Load так, чтобы AMSI не видел payload. После этого скрипт с -enc или с Invoke-Mimikatz не светится по контенту.

**Что видно.** Процесс powershell (или другой хост скриптов) загружает модуль amsi.dll, потом в том же процессе происходит изменение памяти в области amsi.dll (VirtualProtect + write) или загрузка сборки из нестандартного пути. PowerShell с высокими правами (elevated) и при этом загрузка .NET-сборок не из GAC. Событие «AMSI scan» с результатом clean для скрипта с подозрительными ключевыми словами (если EDR логирует контент) — нереально чисто, значит что-то отключили. Краш или выгрузка amsi.dll в процессе powershell до выполнения скрипта.

**Где искать.** События загрузки модуля amsi.dll с последующим memory write или protection change в том же процессе. События .NET: загрузка сборки в powershell из пути не C:\Windows\Microsoft.NET. Корреляция: powershell запущен (особенно с -enc, -nop, -w hidden), в течение минуты в процессе — изменение памяти или загрузка сборки. Некоторые EDR отдают «AMSI bypass attempted» — уже готовый сигнал.

**Пример правила.** Процесс = powershell.exe; в течение 60 сек после старта процесса событие = module load, module = amsi.dll; и событие = memory write или protection change с базой в диапазоне amsi.dll. Исключение: легитимные средства в whitelist.

**Запрос.** process = powershell AND (module = amsi.dll OR event = memory_protection_change). Группировка по process_id, окно 120 сек. Дополнительно: .NET assembly load в powershell где path NOT LIKE "%Microsoft.NET%".

---

## ETW patching и отключение логирования

**Что происходит.** Event Tracing for Windows используется и EDR, и системой для части телеметрии. Патч EtwEventWrite или подобных функций в памяти — и часть событий перестаёт уходить. Часто делают вместе с AMSI bypass в одном процессе.

**Что видно.** В процессе (часто powershell, cscript, wscript) загрузка ntdll или kernel32, затем изменение памяти в области этих модулей. Вызовы, которые обычно генерируют ETW-события, перестают появляться в логах для этого процесса. EDR с kernel-компонентом может видеть патч и отдавать «ETW tampering» или «logging disabled».

**Где искать.** Memory write / protection change в ntdll или kernel32 в процессах скриптовых хостов. Корреляция с AMSI bypass — один и тот же процесс патчит и AMSI, и ETW. Правила на «патч критичных для телеметрии функций» если в EDR есть такая категория.

**Пример правила.** Процесс в (powershell, wscript, cscript); событие = memory write; target module in (ntdll, kernel32); окно после старта процесса до 300 сек.

**Запрос.** event IN (memory_write, protection_change) AND process_name IN (powershell, wscript, cscript) AND target_module IN (ntdll, kernel32).

---

## Living off the land (LOLBins)

**Что делают.** Используют подписанные бинарники из системы для загрузки и выполнения кода: mshta, rundll32, regsvr32, certutil, bitsadmin, wmic, msiexec, cmstp, installutil и т.д. Плюсы для атакующего: подпись, путь из System32, часто белый список в EDR по умолчанию. Минус — командная строка и дочерние процессы всё равно видны.

**Что смотреть по каждому.** mshta — вызов с http(s) URL или с путём к .hta файлу с сети. rundll32 — вызов с scrobj.dll или с URL, javascript: или с подозрительным export. regsvr32 — scrobj.dll, /s /n /u с URL. certutil — -urlcache -split -f или -decode с записью в exe. bitsadmin — /transfer с загрузкой exe/script. wmic — process call create с сетевым путём или с cmd. msiexec — установка с http. cmstp — установка inf с скриптом. Командная строка дочернего процесса: если от этих бинов порождается cmd/powershell с -enc или с сетевыми вызовами — цепочка.

**Где искать.** Process create с полем CommandLine. Правила по Image (имя бинарника) + регулярки или подстроки по CommandLine. В продё нужно whitelist: что реально вызывается легитимно (например certutil для обновления корневых сертификатов), остальное алерт или high.

**Примеры правил.** certutil: CommandLine содержит -urlcache, -decode (кроме известных легит-паттернов). mshta: CommandLine содержит http, https, .hta. rundll32: CommandLine содержит scrobj, javascript:, url=. regsvr32: CommandLine содержит scrobj, /s /n /u и url. bitsadmin: CommandLine содержит /transfer и .exe или .ps1. Для каждого — свой rule id и приоритет.

**Запрос.** process_create WHERE Image IN (certutil, mshta, rundll32, regsvr32, bitsadmin, wmic, msiexec) AND CommandLine RLIKE "http|https|-enc|/transfer|scrobj|urlcache|decode". Разбить по Image и сужать регулярки под свою среду.

---

## In-memory execution без нового exe на диске

**Что происходит.** Шеллкод или .NET загружаются в память существующего процесса: PowerShell Runspace, Assembly.Load(byte[]), NtCreateSection + NtMapViewOfSection с executable, классическая цепочка VirtualAlloc + WriteProcessMemory + CreateRemoteThread. Файла на диске нет, только образ в памяти. Часто жертва процесса — Office, браузер, или легитимный инжектор.

**Что видно.** Загрузка .NET-сборки в процесс: путь не из GAC, не из папки приложения — из temp, из сети, или «in-memory». Создание секции с атрибутами executable и маппинг в процесс. В одном процессе последовательность: аллокация с RW/RWX, запись (или отображение), смена защиты на X или создание потока с entry point в этой области. Процесс офисного приложения (winword, excel) с загрузкой скрипт-движков (PowerShell, VBScript) и последующими сетевыми соединениями или созданием процессов — типичная цепочка после эксплуатации.

**Где искать.** События: .NET assembly load (path, source), section create/map, memory allocation с атрибутами, thread create с start address вне загруженных модулей. Корреляция: один process_guid — alloc (executable) + execution или thread create с нестандартным entry. Офис + загрузка сборки не из GAC + сеть/новый процесс — отдельное правило.

**Пример правила.** За 5 минут в одном процессе: событие allocation с executable; событие thread create с start address не в списке баз загруженных модулей. Или: process = winword/excel/outlook AND event = assembly_load AND path NOT LIKE "%Microsoft.NET%" AND path NOT LIKE "%Program Files%".

**Запрос.** JOIN по process_guid: (event = allocation AND protection IN (PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ)) и (event = thread_create AND start_address NOT IN module_bases). Окно 300 сек. Отдельно: event = assembly_load AND process_name IN (winword, excel) AND path NOT LIKE "%GAC%".

---

## Process hollowing и маскировка под легитимный процесс

**Что происходит.** Создают процесс в suspended state, размаппивают или перезаписывают его образ в памяти, пишут свой код, возобновляют поток. В логах виден «нормальный» путь к exe (например svchost из System32), а по факту выполняется другой код. Либо копия легитимного exe кладётся в другую папку и оттуда запускается (DLL side-load рядом с ним).

**Что видно.** Процесс с Image path из System32, но хеш файла не совпадает с референсным (например не тот svchost). Путь к образу не стандартный: svchost не из C:\Windows\System32. Загрузка DLL из папки процесса (DLL search order): приложение тянет dll из своей директории, а не из System32 — side-load. Редко: создание процесса suspended и последующее изменение памяти до resume — если EDR это отдаёт.

**Где искать.** Process create: сравнение (Image path, file hash) с эталоном. Если хеш неизвестный или не из whitelist для этого пути — алерт. Процесс с именем системного (svchost, csrss, lsass, winlogon) но path не System32/SysWOW64. События загрузки DLL: module path из папки exe с подозрительным именем (например версия легитимной dll с другим именем).

**Пример правила.** process_create WHERE Image LIKE "%svchost%" AND Image path NOT LIKE "%System32%". process_create WHERE Image IN (csrss, lsass, winlogon) AND path NOT IN allowed_paths. file hash для Image не в списке известных хороших для данного path.

**Запрос.** process_create WHERE (Image CONTAINS "svchost" OR "csrss" OR "lsass") AND path NOT STARTS WITH "C:\\Windows\\System32". Плюс отдельная таблица/список allowed hashes по path; событие с hash NOT IN list.

---

## Token manipulation и elevation

**Что происходит.** Крадут или дублируют токен привилегированного процесса (например lsass или сервиса), создают процесс с этим токеном или подменяют токен текущего потока. В логах видно: процесс с неожиданно высокими правами, открытие lsass с определенными правами, дублирование хендла токена.

**Что видно.** OpenProcess к lsass (или к процессу с высокими привилегиями) с правами PROCESS_QUERY_LIMITED_INFORMATION / PROCESS_VM_READ и т.д. DuplicateHandle на токен. Создание процесса с токеном другого пользователя или с elevated токеном от процесса, который обычно не создаёт такие дочерние процессы. Аномалия: процесс пользователя вне админ-сессии вдруг создаёт сервис или процесс с системными правами.

**Где искать.** События open process с target = lsass или системный процесс; duplicate handle (token). Process create с полем token или integrity — несоответствие ожидаемому пользователю/уровню. Корреляция: open lsass → duplicate handle → create process с elevated.

**Пример правила.** OpenProcess где target = lsass и requested access включает VM_READ или аналоги. Process create где parent не system/svchost но integrity = high или user = SYSTEM.

**Запрос.** event = process_open AND target_process = lsass AND access_mask IN (VM_READ, ...). process_create WHERE integrity = high AND parent_integrity = medium.

---

## Отключение и обход компонентов EDR/AV

**Что делают.** Останавливают сервис или процесс агента, меняют реестр (отключение real-time scan, исключения путей), загружают свой драйвер или эксплуатируют уязвимость в драйвере EDR. Иногда достаточно прав пользователя (например запись в свой профиль или в реестр текущего пользователя).

**Что видно.** Process terminate или service stop — target имя процесса/сервиса EDR или AV (у каждого вендора свои имена, нужно собрать список). Registry set в ключах типа DisableRealtimeMonitoring, EnableControlledFolderAccess, исключений путей. Загрузка драйвера: образ не из C:\Windows\System32\drivers или неподписанный/подписанный не вендором ОС. Краш процесса агента или перезапуск сервиса — в логах виден stop и потом start.

**Где искать.** События process terminate, service control (stop) с target по списку имён EDR/AV. Registry events по путям, связанным с безопасностью. Driver load с путём и подписью. Алерты от самого EDR на «tampering» или «component disabled».

**Пример правила.** Blacklist по target name при terminate/stop: имена процессов и сервисов всех установленных агентов. Реестр: изменения в HKLM\...\Windows Defender, в ключах отключения. Driver load: path не System32\drivers или signer не Microsoft/ваш вендор.

**Запрос.** event IN (process_terminate, service_stop) AND target_name IN (список_агентов). registry WHERE path CONTAINS "DisableRealtimeMonitoring" OR path CONTAINS "ExclusionPath". driver_load WHERE path NOT LIKE "%System32\\drivers%".

---

## Сводка по SIEM и приоритетам

Одним запросом всё не закрыть. Лучше завести отдельные правила (или сохранённые запросы) под каждую технику: unhooking, direct syscall, parent spoofing, AMSI/ETW bypass, LOLBins по бинарникам, in-memory execution, process hollowing/маскировка, token manipulation, действия против EDR. События брать из того, что реально отдаёт твой EDR в SIEM — у каждого вендора свои имена полей и типы событий. После первых срабатываний обязательно донастроить исключения и whitelist по своей среде, иначе будет шум и правила отключат. Имеет смысл мапить правила на MITRE ATT&CK (Defense Evasion, Execution, Privilege Escalation) — так и в отчётах понятно, и в проде проще поддерживать и объяснять алерты.
