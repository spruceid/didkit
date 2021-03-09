<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<html>
<head>
    <title>Java JSP Example - Get Status Credential</title>
</head>
<body>
<p><a href="${pageContext.request.contextPath}/">Back</a></p>
<form method="post" action="${pageContext.request.contextPath}/credential/status">
    <p><label>DID:<input id="did" name="did" placeholder="did:example:abcd1234"/></label></p>
    <p><label>Status:<input id="status" name="status" placeholder="Lawyer, Accountant, ..."/></label></p>
    <p><input type="submit" value="Get Credential"/></p>
</form>
</body>
</html>
