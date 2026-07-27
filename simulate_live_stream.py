import asyncio
import websockets
import json
import pandas as pd
import time

async def stream_hospital_logs():
    uri = "ws://127.0.0.1:8000/ws/live-logs"
    
    # قراءة سجلات المستشفى للتغذية منها حياً
    try:
        logs_df = pd.read_csv("hospital_logs.csv")
    except Exception as e:
        print("خطأ: تعذر قراءة hospital_logs.csv")
        return

    print("جاري الاتصال بخادم الـ FastAPI عبر قناة WebSocket الحية...\n")
    
    async with websockets.connect(uri) as websocket:
        print(" تم الاتصال بنجاح! جاري إرسال أحداث المستشفى الحية كل ثانيتين...\n")
        
        for index, row in logs_df.iterrows():
            log_payload = {
                "log_id": str(row["log_id"]),
                "department": str(row["department"]),
                "destination_target": str(row["destination_target"]),
                "data_mb": float(row["data_mb"]),
                "is_admin_user": int(row["is_admin_user"]),
                "hour_of_day": int(row["hour_of_day"])
            }
            
            # 1. إرسال الـ Log عبر الـ WebSocket
            await websocket.send(json.dumps(log_payload))
            
            # 2. استقبال النتيجة الفورية المعالجة بالـ Machine Learning
            response = await websocket.recv()
            result = json.loads(response)
            
            # طباعة النتيجة بتنسيق جذاب في الـ Terminal
            status_symbol = "🚨 [THREAT DETECTED]" if result["is_threat"] == 1 else "✅ [SAFE]"
            print(f"{status_symbol} | Log: {result['log_id']} | Dept: {result['department']} | Target: {result['destination_target']} | Data: {result['data_mb']} MB")
            
            # الانتظار ثانيتين قبل إرسال الأحداث التالية (حجم البث الحي)
            await asyncio.sleep(2)

# تثبيت مكتبة websockets إذا لم تكن موجودة
if __name__ == "__main__":
    try:
        asyncio.run(stream_hospital_logs())
    except KeyboardInterrupt:
        print("\nتم إيقاف البث الحي.")