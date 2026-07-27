import pandas as pd
import random
from datetime import datetime, timedelta

print("جاري قراءة مؤشرات الاختراق من OTX وتوليد Logs محاكاة للمستشفى...")

# 1. قراءة الـ IoCs التي سحبناها سابقاً
try:
    otx_df = pd.read_csv("healthcare_iocs.csv")
    bad_indicators = otx_df['indicator_value'].tolist()
except Exception as e:
    print("خطأ: يرجى التأكد من وجود ملف healthcare_iocs.csv في نفس المجلد!")
    exit()

# قائمة بعناوين آمنة وموثوقة للمحاكاة
safe_indicators = [
    "google.com", "microsoft.com", "moh.gov.jo", "10.0.0.15", 
    "10.0.0.22", "192.168.1.50", "mayoclinic.org", "internal-portal.hospital.local"
]

# أقسام المستشفى
departments = ["Radiology", "Emergency", "ICU", "Pharmacy", "Administration", "Lab"]

logs = []

# توليد 1000 سطر Log للمستشفى
for i in range(1000):
    # اختيار عشوائي: هل الحركة مشبوهة (20% احتمال) أم آمنة (80% احتمال)؟
    is_malicious_attempt = random.random() < 0.20
    
    if is_malicious_attempt and bad_indicators:
        destination = random.choice(bad_indicators) # استخدام مؤشر خبيث حقيقي من OTX
        data_transferred_mb = round(random.uniform(100.0, 5000.0), 2) # حجم بيانات ضخم (سحب بيانات)
        hour = random.choice([1, 2, 3, 4, 23]) # أوقات حرج متأخرة ليلاً
        is_admin = random.choice([0, 1])
    else:
        destination = random.choice(safe_indicators) # استخدام عنوان آمن
        data_transferred_mb = round(random.uniform(0.1, 15.0), 2) # حجم بيانات عادي جداً
        hour = random.randint(8, 17) # أوقات الدوام الرسمي
        is_admin = 0

    # تاريخ عشوائي خلال اليومين الماضيين
    log_time = datetime.now() - timedelta(days=random.randint(0, 2), hours=random.randint(0, 23), minutes=random.randint(0, 59))
    log_time = log_time.replace(hour=hour)

    logs.append({
        "log_id": f"LOG-{1000 + i}",
        "timestamp": log_time.strftime("%Y-%m-%d %H:%M:%S"),
        "department": random.choice(departments),
        "destination_target": destination,
        "data_mb": data_transferred_mb,
        "is_admin_user": is_admin,
        "hour_of_day": hour
    })

# تحويل البيانات لجدول وحفظها
logs_df = pd.DataFrame(logs)
logs_df.to_csv("hospital_logs.csv", index=False)

print(f" تم بنجاح إنشاء {len(logs_df)} سطر Log للمستشفى وحفظها في 'hospital_logs.csv'!")
print("\nعينة من سجلات المستشفى المولدّة:")
print(logs_df.head())