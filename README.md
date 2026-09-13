# PhishGuard

**Intelligent Phishing Detection System** — أداة محلية قابلة للتفسير لاكتشاف مؤشرات التصيد الاحتيالي.

## وصف مختصر

PhishGuard أداة CLI مكتوبة باستخدام **Pure Python** ومن دون مكتبات خارجية. تفحص الروابط، والنصوص، ورسائل البريد، والملفات النصية، وملفات CSV، ثم تعطي قراراً واضحاً مع درجة خطر ومؤشرات تفسيرية.

الفحص محلي بالكامل؛ لا يفتح البرنامج الروابط ولا يرسل المحتوى إلى خدمة خارجية.

> ملاحظة: نتيجة `SAFE` تعني عدم العثور على مؤشرات ضمن القواعد الحالية، ولا تمثل ضماناً مطلقاً للأمان.

## المتطلبات

يحتاج المشروع إلى Python 3.9 أو أحدث، ولا يحتاج إلى `pip install` أو أي مكتبات خارجية.

## التشغيل السريع

```bash
python run.py --help
python run.py --version
python run.py scan --url "https://example.com/about"
python run.py scan --url "http://192.168.1.10/login?password=demo"
python run.py scan --file examples/suspicious_message.eml
python run.py batch examples/targets.csv
```

في Linux يمكن استخدام `python3` بدلاً من `python`.

## الأوامر

| الأمر | الوظيفة |
|---|---|
| `scan --url URL` | فحص رابط واحد دون فتحه |
| `scan --text TEXT` | فحص رسالة أو نص |
| `scan --file FILE` | فحص ملف نصي مدعوم |
| `batch CSV_FILE` | فحص مجموعة أهداف من CSV |
| `init-config FILE` | إنشاء ملف إعدادات نموذجي |

الخيارات العامة المدعومة هي `--help` و`--version` و`--config` و`--log-level`.

### إخراج JSON وحفظ النتائج

```bash
python run.py scan --url "https://bit.ly/verify" --format json
python run.py scan --file examples/suspicious_message.eml --format json --output reports/result.json
python run.py batch examples/targets.csv --format json --output reports/batch.json
```

ينشئ البرنامج مجلد النتائج تلقائياً عند استخدام `--output`.

## درجات الخطر

| القرار | الدرجة | المعنى |
|---|---:|---|
| `SAFE` | 0–24 | لم تظهر مؤشرات قوية ضمن القواعد الحالية. |
| `SUSPICIOUS` | 25–54 | توجد مؤشرات تحتاج إلى تحقق يدوي. |
| `HIGH_RISK` | 55–79 | لا يُنصح بفتح الرابط أو إدخال البيانات. |
| `CRITICAL` | 80–100 | تعامل مع الهدف كتصيد محتمل جداً. |

## الاختبارات

```bash
python -m unittest discover -s tests -v
```

## هيكل المشروع

```text
PhishGuard/
├── run.py
├── phishguard/
│   ├── cli.py
│   ├── config.py
│   ├── models.py
│   ├── rules.py
│   ├── scanner.py
│   └── __main__.py
├── tests/
├── examples/
├── docs/
└── .github/workflows/tests.yml
```

## التوثيق

للدليل العربي الكامل راجع [`docs/usage_guide_ar.md`](docs/usage_guide_ar.md). يحتوي المشروع أيضاً على تقرير المشروع، وقائمة العرض العملي، ومصفوفة مطابقة ضوابط `PLC-PR`.

## ضوابط الأمان والخصوصية

لا ينفذ PhishGuard اتصالات شبكية في النسخة الحالية. يقرأ الملفات النصية المدعومة فقط، ويتحقق من حجم الملف وترميزه وامتداده، ويتعامل مع الأخطاء برسائل واضحة دون عرض tracebacks للمستخدم.

## الترخيص

هذا المشروع تعليمي ومخصص للتطوير والعرض الأكاديمي. راجع ملف [`LICENSE`](LICENSE) قبل إعادة الاستخدام أو التوزيع.
