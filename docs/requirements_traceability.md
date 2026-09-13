# مصفوفة التوافق مع ضوابط PLC-PR

| بند الضابط | تطبيقه في PhishGuard | مكان التحقق |
|---|---|---|
| فكرة عملية في الأمن السيبراني | فحص الروابط والرسائل والملفات ضد مؤشرات التصيد | `README.md` و`docs/project_report.md` |
| Pure Python | النواة مكتوبة بالمكتبة القياسية فقط | جميع ملفات `phishguard/` |
| عدم استخدام Third-party Libraries | لا يوجد `requirements.txt` ولا import خارجي | الشيفرة والاختبارات |
| تشغيل موحد | `python run.py ...` أو `python -m phishguard ...` | `run.py` و`phishguard/__main__.py` |
| واجهة CLI رئيسية | `argparse` مع أوامر فرعية | `phishguard/cli.py` |
| Subcommands | `scan` و`batch` و`init-config` | `phishguard/cli.py` |
| `--help` | مدعوم على الجذر وكل أمر | `build_parser()` |
| `--version` | يعرض `PhishGuard 1.0.0` | `build_parser()` |
| `--config` | يقرأ JSON ويتحقق من القيم | `config.py` و`cli.py` |
| `--log-level` | يضبط مستوى سجل Python | `config.py` و`cli.py` |
| Windows وLinux | استخدام `pathlib` وعدم افتراض shell معين | `scanner.py` و`run.py` |
| إدخال غير صحيح | التحقق من الرابط والنص والـCSV | `scanner.py` |
| ملف غير موجود | `FileNotFoundError` برسالة عربية | `scanner.py` و`cli.py` |
| ملف إعدادات تالف | `ConfigurationError` برسالة مفهومة | `config.py` |
| نقص الصلاحيات | التقاط `PermissionError` | `config.py` و`scanner.py` و`cli.py` |
| فشل اتصال/المهلات | لا يوجد اتصال شبكي في النسخة المحلية | `metadata.network_access = False` |
| التوثيق | شرح المشكلة والفكرة والأهداف والتشغيل والمخرجات | `README.md` و`docs/` |
| العرض العملي | أوامر وبيانات جاهزة | `docs/demo_checklist.md` و`examples/` |
| إضافة مميزة | فحص دفعي CSV، JSON، SHA-256 للملفات، ثقة تفسيرية، ورموز خروج آلية | `scanner.py` و`cli.py` |
| قابلية التطوير | القواعد والنماذج والفحص مفصولة | بنية الحزمة |
