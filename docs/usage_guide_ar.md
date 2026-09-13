# دليل استخدام PhishGuard بالتفصيل

## 1. المتطلبات الأولية

يحتاج PhishGuard إلى Python 3.9 أو إصدار أحدث. لا يحتاج المشروع إلى تثبيت أي مكتبات خارجية أو تنفيذ `pip install`، لأن جميع مكوناته مبنية باستخدام مكتبات Python القياسية.

بعد فك ضغط المشروع، افتح Terminal أو PowerShell وانتقل إلى مجلد المشروع:

```bash
cd PhishGuard
```

على Windows يمكن استخدام:

```powershell
cd C:\Users\اسمك\Downloads\PhishGuard
```

وعلى Linux أو macOS يمكن استخدام:

```bash
cd ~/Downloads/PhishGuard
```

> إذا كان أمر `python` لا يعمل في Linux، جرّب `python3` بدلاً منه. في الأمثلة التالية يمكن استبدال `python` بـ `python3` عند الحاجة.

## 2. الصيغة الأساسية للتشغيل

الأمر الرسمي للتشغيل هو:

```bash
python run.py <الأمر> [الخيارات]
```

كما توجد صيغة بديلة مكافئة:

```bash
python -m phishguard <الأمر> [الخيارات]
```

يفضل استخدام `run.py` في العرض لأنه أوضح وأسهل للطلاب والمقيّمين.

## 3. عرض المساعدة

لعرض المساعدة العامة:

```bash
python run.py --help
```

يعرض هذا الأمر اسم المشروع ووصفه والأوامر المتاحة وملاحظة أن الفحص محلي ولا يفتح الروابط.

لعرض مساعدة أمر الفحص:

```bash
python run.py scan --help
```

ولعرض مساعدة الفحص الدفعي:

```bash
python run.py batch --help
```

## 4. عرض الإصدار

لعرض إصدار البرنامج:

```bash
python run.py --version
```

الناتج المتوقع:

```text
PhishGuard 1.0.0
```

## 5. الأمر scan

يستخدم الأمر `scan` لفحص هدف واحد. يجب اختيار نوع واحد فقط من الأنواع التالية: رابط، نص، أو ملف.

### 5.1 فحص رابط آمن

```bash
python run.py scan --url "https://example.com/about"
```

يفحص البرنامج تركيب الرابط دون فتحه. في هذه الحالة غالباً تظهر نتيجة قريبة من:

```text
القرار      : آمن (SAFE)
درجة الخطر  : 0/100
الثقة       : 92%
المؤشرات    : 0
```

معنى `SAFE` أن القواعد المحلية لم تجد مؤشرات قوية، وليس معنى ذلك أن الرابط مضمون بنسبة 100%.

### 5.2 فحص رابط مشبوه

```bash
python run.py scan --url "http://192.168.1.10/login?password=demo"
```

قد يكتشف البرنامج عدة مؤشرات، مثل استخدام HTTP، واستخدام عنوان IP، ووجود مسار متعلق بتسجيل الدخول أو كلمة المرور. النتيجة تكون غالباً `HIGH_RISK` أو `CRITICAL` حسب مجموع النقاط.

### 5.3 فحص رابط يحتوي على رمز @

```bash
python run.py scan --url "https://paypal.com@malicious.example/login"
```

وجود `@` داخل الرابط قد يجعل المستخدم يظن أن الوجهة هي `paypal.com`، بينما المضيف الحقيقي هو الجزء الموجود بعد الرمز. يعرض PhishGuard هذا المؤشر باسم `URL004`.

### 5.4 فحص رابط مختصر

```bash
python run.py scan --url "https://bit.ly/verify-account"
```

يكتشف البرنامج خدمة اختصار الرابط ويضيف مؤشراً لأن الوجهة النهائية غير ظاهرة للمستخدم مباشرة.

### 5.5 فحص نص رسالة بريد أو بلاغ

```bash
python run.py scan --text "URGENT: verify your account password immediately at http://192.168.1.10/login"
```

يحلل البرنامج النص بحثاً عن كلمات الاستعجال، وطلبات بيانات الدخول، والموضوعات المالية، والروابط الموجودة داخل النص. كما يعيد فحص الروابط المضمنة في الرسالة تلقائياً.

يمكن تمرير نص عربي أيضاً:

```bash
python run.py scan --text "عاجل: تحقق من حسابك وكلمة المرور فوراً عبر https://bit.ly/account"
```

### 5.6 فحص ملف نصي

```bash
python run.py scan --file examples/suspicious_message.eml
```

الامتدادات المدعومة هي:

| الامتداد | الاستخدام |
|---|---|
| `.txt` | ملف نص عادي |
| `.eml` | رسالة بريد محفوظة |
| `.html` و`.htm` | صفحة أو رسالة HTML كنص |
| `.csv` | ملف بيانات نصي للفحص الفردي عند الحاجة |
| `.json` | ملف JSON نصي |
| `.md` | ملف Markdown |
| `.log` | ملف سجلات نصي |

الحد الافتراضي لحجم الملف هو 5 MB، ويمكن تغييره من ملف الإعدادات.

## 6. تنسيق النتائج

### 6.1 العرض الافتراضي في جدول

```bash
python run.py scan --url "https://example.com"
```

العرض الجدولي مناسب للعرض المباشر أمام المقيّم، لأنه يوضح الهدف والقرار والدرجة والمؤشرات بالتفصيل.

### 6.2 العرض بصيغة JSON

```bash
python run.py scan --url "http://192.168.1.10/login" --format json
```

صيغة JSON مناسبة للبرامج الأخرى أو للحفظ والتحليل البرمجي. تحتوي النتيجة على:

| الحقل | المعنى |
|---|---|
| `target` | الرابط أو النص أو اسم الملف المفحوص |
| `target_type` | نوع الهدف: `url` أو `text` أو `file` |
| `verdict` | القرار النهائي |
| `risk_score` | درجة الخطر من 0 إلى 100 |
| `confidence` | ثقة تفسيرية وليست احتمالاً إحصائياً |
| `findings` | قائمة المؤشرات المكتشفة |
| `metadata` | معلومات إضافية عن الهدف |
| `scanned_at` | وقت الفحص بصيغة UTC |

### 6.3 حفظ النتيجة في ملف

```bash
python run.py scan --url "http://192.168.1.10/login" --format json --output reports/result.json
```

ينشئ البرنامج مجلد `reports` تلقائياً إذا لم يكن موجوداً، ثم يحفظ النتيجة في الملف المحدد.

يمكن حفظ فحص ملف أيضاً:

```bash
python run.py scan --file examples/suspicious_message.eml --format json --output reports/message.json
```

عند فحص الملفات، يضيف JSON قيمة `sha256` التي تمثل بصمة محتوى الملف للمقارنة والتوثيق.

### 6.4 الوضع الهادئ

```bash
python run.py scan --url "https://example.com" --format quiet
```

يستخدم الوضع الهادئ عند استدعاء الأداة من سكربت أو نظام آلي عندما لا تريد عرض تفاصيل النتيجة على الشاشة. يبقى رمز الخروج متاحاً للبرنامج المستدعي.

## 7. الأمر batch

يستخدم `batch` لفحص عدة أهداف من ملف CSV. يجب أن يحتوي الملف على عمود باسم واحد من الأسماء التالية:

```text
url
```

أو:

```text
target
```

أو:

```text
link
```

أو:

```text
text
```

يوجد ملف جاهز للتجربة في:

```text
examples/targets.csv
```

### 7.1 الفحص الدفعي في جدول

```bash
python run.py batch examples/targets.csv
```

يعرض البرنامج العدد الإجمالي ومتوسط درجة الخطر وتوزيع القرارات وعدد العناصر عالية الخطورة، ثم يعرض جدولاً مختصراً لكل صف.

### 7.2 الفحص الدفعي بصيغة JSON

```bash
python run.py batch examples/targets.csv --format json
```

ينتج JSON يحتوي على كائنين رئيسيين:

```json
{
  "summary": {},
  "results": []
}
```

يحتوي `summary` على الإحصاءات العامة، بينما يحتوي `results` على تفاصيل كل هدف.

### 7.3 حفظ نتائج الفحص الدفعي

```bash
python run.py batch examples/targets.csv --format json --output reports/batch.json
```

## 8. الأمر init-config

ينشئ الأمر `init-config` ملف إعدادات JSON نموذجياً:

```bash
python run.py init-config phishguard.json
```

الناتج المتوقع:

```text
تم إنشاء ملف الإعدادات: phishguard.json
```

محتوى الملف النموذجي:

```json
{
  "output_format": "table",
  "max_file_mb": 5,
  "network_access": false,
  "log_level": "WARNING"
}
```

يمكن إنشاء الملف داخل مجلد جديد:

```bash
python run.py init-config config/phishguard.json
```

### معنى إعدادات JSON

| الإعداد | القيم | الوظيفة |
|---|---|---|
| `output_format` | `table` أو `json` أو `quiet` | التنسيق الافتراضي للنتائج |
| `max_file_mb` | رقم موجب | أقصى حجم للملف بالميغابايت |
| `network_access` | `false` | يوضح أن الفحص المحلي لا يستخدم الشبكة |
| `log_level` | `DEBUG` أو `INFO` أو `WARNING` أو `ERROR` أو `CRITICAL` | مستوى السجلات |

## 9. استخدام --config

لتشغيل الأداة باستخدام ملف إعدادات:

```bash
python run.py --config phishguard.json scan --url "https://example.com"
```

ويمكن وضع `--config` بعد اسم الأمر أيضاً:

```bash
python run.py scan --config phishguard.json --url "https://example.com"
```

إذا كان ملف الإعدادات تالفاً أو يحتوي قيمة غير صحيحة، تظهر رسالة واضحة مثل:

```text
خطأ: ملف الإعدادات ليس JSON صالحاً.
```

## 10. استخدام --log-level

لرفع مستوى التفاصيل أثناء التشخيص:

```bash
python run.py --log-level INFO scan --url "https://example.com"
```

أو:

```bash
python run.py scan --log-level DEBUG --url "https://example.com"
```

في التشغيل العادي يكفي `WARNING`. لا يعرض البرنامج أخطاء Python الداخلية للمستخدم، حتى عند حدوث مشكلة غير متوقعة.

## 11. تفسير القرارات

| القرار | الدرجة | التفسير |
|---|---:|---|
| `SAFE` | من 0 إلى 24 | لم تظهر مؤشرات قوية في القواعد الحالية. |
| `SUSPICIOUS` | من 25 إلى 54 | توجد مؤشرات تستحق التحقق اليدوي. |
| `HIGH_RISK` | من 55 إلى 79 | توجد مؤشرات قوية؛ لا تفتح الرابط ولا تدخل بياناتك. |
| `CRITICAL` | من 80 إلى 100 | مؤشرات شديدة الخطورة؛ تعامل معه كتصيد محتمل جداً. |

## 12. رموز الخروج

يمكن معرفة نجاح الأمر من خلال رمز الخروج:

| الرمز | المعنى |
|---:|---|
| `0` | تم الفحص بنجاح ولم توجد نتيجة عالية الخطورة أو حرجة. |
| `1` | حدث خطأ في الإدخال أو الملف أو الإعدادات أو نظام الملفات. |
| `2` | تم الفحص بنجاح، لكن النتيجة `HIGH_RISK` أو `CRITICAL`. |

في PowerShell يمكن عرض رمز الخروج بعد الأمر باستخدام:

```powershell
$LASTEXITCODE
```

وفي Linux يمكن استخدام:

```bash
echo $?
```

مثال للاستفادة من رمز الخروج في سكربت:

```bash
python run.py scan --url "http://192.168.1.10/login"
if [ $? -eq 2 ]; then
    echo "تحذير: الهدف عالي الخطورة"
fi
```

## 13. حالات الأخطاء الشائعة

### رابط غير صحيح

الأمر:

```bash
python run.py scan --url "not-a-url"
```

الناتج:

```text
خطأ: صيغة الرابط غير صحيحة. استخدم مثالاً مثل https://example.com.
```

### ملف غير موجود

```bash
python run.py scan --file missing.eml
```

الناتج:

```text
خطأ: الملف غير موجود: missing.eml
```

### امتداد غير مدعوم

```bash
python run.py scan --file image.png
```

الناتج يوضح أن الامتداد غير مدعوم، لأن النسخة الحالية تقرأ الملفات النصية فقط.

### ملف إعدادات تالف

إذا كان JSON غير صحيح، يظهر:

```text
خطأ: ملف الإعدادات ليس JSON صالحاً.
```

### ملف CSV بلا عمود مناسب

إذا لم يحتوي CSV على `url` أو `target` أو `link` أو `text`، يظهر خطأ يوضح أسماء الأعمدة المقبولة.

## 14. أوامر العرض المقترحة

استخدم التسلسل التالي في المناقشة:

```bash
python run.py --version
python run.py --help
python run.py scan --url "https://example.com/about"
python run.py scan --url "http://192.168.1.10/login?password=demo"
python run.py scan --file examples/suspicious_message.eml
python run.py batch examples/targets.csv
python run.py batch examples/targets.csv --format json --output reports/demo.json
python -m unittest discover -s tests -v
```

في أثناء العرض اشرح أن الفحص محلي، وأن القرار مبني على مؤشرات قابلة للتفسير، وأن `SAFE` لا يعني ضمان الأمان المطلق. اختم بعرض بنية الملفات وقواعد التصنيف ورموز الخروج.

## 15. تشغيل الاختبارات

من مجلد المشروع:

```bash
python -m unittest discover -s tests -v
```

إذا ظهرت عبارة `OK` فهذا يعني أن الاختبارات الحالية مرّت بنجاح. الاختبارات تغطي الرابط الآمن، الرابط عالي الخطورة، النص المشبوه، الملف، CSV، الرابط غير الصحيح، وملف الإعدادات التالف.
