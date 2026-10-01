/**
 * Google Apps Script Webhook for Secure Motion Logger
 * Receives decrypted and authenticated telemetry from the Kali Linux Secure Gateway.
 * Validates the security token and appends telemetry to Google Sheets in real-time.
 */

// --- KONFIGURASI KEAMANAN ---
// Token ini berfungsi sebagai autentikasi API tingkat aplikasi di sisi cloud.
var SECURITY_TOKEN = "akses_aman_123";

/**
 * HTTP POST Handler for incoming telemetry payloads
 */
function doPost(e) {
  // 1. Validasi request payload
  if (!e || !e.postData || !e.postData.contents) {
    return ContentService.createTextOutput("Error: Data Kosong")
      .setMimeType(ContentService.MimeType.TEXT);
  }

  try {
    // 2. Parsing payload JSON dari gateway subscriber
    var data = JSON.parse(e.postData.contents);

    // 3. Autentikasi: Verifikasi token keamanan
    if (data.token !== SECURITY_TOKEN) {
      return ContentService.createTextOutput("Error: Token Salah! Akses Ditolak.")
        .setMimeType(ContentService.MimeType.TEXT);
    }

    // 4. Logging ke Google Spreadsheet
    var sheet = SpreadsheetApp.getActiveSpreadsheet().getActiveSheet();
    var waktu = new Date(); // Timestamp server

    // Skema kolom: [Waktu, Suhu, Gyro X, Gyro Y, Gyro Z]
    sheet.appendRow([
      waktu,
      data.temp,
      data.gx,
      data.gy,
      data.gz
    ]);

    // 5. Respons sukses ke gateway
    return ContentService.createTextOutput("Sukses: Data Masuk")
      .setMimeType(ContentService.MimeType.TEXT);

  } catch (error) {
    // Error handling
    return ContentService.createTextOutput("Error Server: " + error.message)
      .setMimeType(ContentService.MimeType.TEXT);
  }
}

/**
 * Opsional: HTTP GET Handler untuk pengecekan status server (healthcheck)
 */
function doGet(e) {
  return ContentService.createTextOutput("Secure Motion Logger Cloud Webhook is Active.")
    .setMimeType(ContentService.MimeType.TEXT);
}
