# Покрытие T1055 (Linux, измерено)

> Сгенерировано `scripts/t1055_coverage.py` — 2026-11-13T21:42 UTC.

Путей измерено: **4**; алерт-уровень: **3**, признак-уровень: **1**; событий 400, вердиктов 400, потерь 0.

## Пути

| Путь | Источник | Уровень | События | Вердикты | Контроль | Потери |
|---|---|---|---|---|---|---|
| process_vm_writev | linux.memory | **alert** | 100 | 100 | 0 | 0 |
| ptrace POKE* | linux.ptrace | **alert** | 100 | 100 | 0 | 0 |
| /proc/<pid>/mem | linux.procmem | **alert** | 100 | 100 | 0 | 0 |
| mprotect PROT_EXEC | linux.mprotect | **signal** | 100 | 100 | 0 | 0 |

## Лестница правил (наращивание контекста)

| Слой | Правило | Группировка | Алерты | Измеренные FP | Вывод |
|---|---|---|---|---|---|
| 0 | `LINUX-EXEC-MEM-107` | none | 100 | JIT noise: 0 non-helper events in the run | signal only (medium), never an alert alone |
| 1 | `LINUX-EXEC-CORR-108` | actor.pid | 5 | JIT-only phase: 0 alerts | alert on injection, quiet on JIT |
| 2 | `LINUX-EXEC-CORR-109` | process_tree | 1 | legit supervisor+JIT: 1 alert(s); benign JIT: 0 | catches parent-writes-child-executes, known FP class |
| 3 | `LINUX-EXEC-CORR-110` | process_tree + provenance | 1 | trusted supervisor: 0 alert(s); path from kernel: 20, fallback: 0 | preferred: FP removed, detection kept |

## Что значит «признак»
`signal` — путь записан и виден, но сам по себе не алертит: JIT-движки дают тот же паттерн, поэтому нужен корреляционный контекст (происхождение процесса, запуск с диска, аномальная последовательность).

## Дыры (осознанные, не закрыты)
- **mprotect without correlation**: JIT and injection share the pattern; the signal alone is not an alert.
- **dlopen / LD_PRELOAD**: loads code into the attacker's own process; not a cross-process write, different detection (module load).
- **/dev/mem**: requires root and is usually disabled; not measured.
- **Windows T1055**: ETW-TI requires elevation (blocker D); not measured.
- **argv[0] spoofing**: provenance uses mm->exe_file, so a renamed argv is invisible by design; documented as a non-goal.

## Что это НЕ доказывает
Матрица показывает, что каждый путь наблюдается и даёт вердикт — она не доказывает, что реальный adversary будет пойман: нет red-team, нет обхода через другие примитивы, Windows-часть не измерена (нужна элевация).
