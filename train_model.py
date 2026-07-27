import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

print("1. جاري قراءة ملفات البيانات وتطبيق الـ Matching Concept...")

# قراءة البيانات
iocs_df = pd.read_csv("healthcare_iocs.csv")
logs_df = pd.read_csv("hospital_logs.csv")

# استخراج قائمة المؤشرات المشبوهة لعمل الـ Matching
bad_indicators_set = set(iocs_df['indicator_value'].tolist())

# تطبيق الـ Matching Concept: إنشاء feature جديدة
logs_df['is_in_otx'] = logs_df['destination_target'].apply(lambda x: 1 if x in bad_indicators_set else 0)

# تحديد الـ Target (النتيجة التي يتعلم منها النموذج)
# يكون هجوماً (1) إذا كان العنوان في OTX وحجم البيانات أكبر من 50MB أو الوقت ليلاً
def label_threat(row):
    if row['is_in_otx'] == 1 and (row['data_mb'] > 50.0 or row['hour_of_day'] in [1, 2, 3, 4, 23]):
        return 1  # Threat / Attack
    return 0     # Safe

logs_df['is_threat'] = logs_df.apply(label_threat, axis=1)

print(f"تم تصنيف البيانات: {sum(logs_df['is_threat'] == 1)} تهديد محتمل مقابل {sum(logs_df['is_threat'] == 0)} حركة آمنة.\n")

# 2. تحديد المدخلات (Features) والمخرجات (Target)
X = logs_df[['data_mb', 'is_admin_user', 'hour_of_day', 'is_in_otx']]
y = logs_df['is_threat']

# تقسيم البيانات إلى 80% تدريب و 20% اختبار
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("2. جاري تدريب خوارزمية Random Forest Classifier...")

# إنشاء وتدريب نموذج Random Forest
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 3. تقييم دقة النموذج
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f" تم تدريب النموذج بنجاح! دقة النموذج (Accuracy): {accuracy * 100:.2f}%\n")
print("تقرير الأداء التفصيلي:")
print(classification_report(y_test, y_pred))

# 4. حفظ النموذج الجاهز لاستخدامه في الـ Back-End
joblib.dump(model, "threat_model.pkl")
print(" تم حفظ النموذج الجاهز في ملف 'threat_model.pkl' بنجاح!")