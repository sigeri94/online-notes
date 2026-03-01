```powershell
cd C:\path\to\file-upload
javac -cp "c:\tomcat\lib\servlet-api.jar" -d WEB-INF\classes src\simple\FileUploadServlet.java

jar -cvf file-upload.war *
```
