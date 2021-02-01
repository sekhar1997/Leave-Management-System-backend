class ReplaceableObject(object):
    def __init__(self, name, sqltext):
        self.name = name
        self.sqltext = sqltext


Employees_trigger = ReplaceableObject(
    "Employees_trigger()",
    """
    RETURNS trigger AS
    $BODY$
    BEGIN
    NEW."employeeId" := (select TO_CHAR(nextval('employee_seq_autoid'::regclass),'"1xE"fm000000'));
    RETURN NEW;
    END;
    $BODY$
    LANGUAGE plpgsql VOLATILE
    COST 100;
    
    CREATE TRIGGER TrgEmployee
    BEFORE INSERT ON "Employee"
    FOR EACH ROW
    EXECUTE PROCEDURE Employees_trigger();
    """
)

Leave_trigger = ReplaceableObject(
    "Leave_trigger()",
    """
    RETURNS trigger AS
    $BODY$
    BEGIN
    NEW."leaveId" := (select TO_CHAR(nextval('leavemanagement_seq_autoid'::regclass),'"1xL"fm000000'));
    RETURN NEW;
    END;
    $BODY$
    LANGUAGE plpgsql VOLATILE
    COST 100;
    
    CREATE TRIGGER TrgLeaveManagement
    BEFORE INSERT ON "LeaveManagement"
    FOR EACH ROW
    EXECUTE PROCEDURE Leave_trigger();
    """
)
