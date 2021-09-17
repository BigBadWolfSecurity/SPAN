class TestRunner:
    def __init__(self) -> None:
        self.all_test_passed = True
        self.terminal_output = open('/dev/stdout', 'w')

    def write_to_term(self, text: str) -> None:
        self.terminal_output.write(text)

    def write_error(self, text: str) -> None:
        self.write_to_term(text)
        self.all_test_passed = False


    def check_table(self, table, vals, access):   
        ret = ""
        if table is None:
            return " "
        if(vals == "*"): # When no access should be allowed
            for count, x in enumerate(table.target.values):
                if(str(x) == access):
                    ret += str(table.loc[[count]]["source"].values)[1:-1] + ", "
        else: # When specific domains should not be allowed
            for x in vals:
                if x in str(table["source"].values):
                    ret += x + ", "

        if ret == "":
            return " "

        ret = ret[:-2] + " has unexpected access to " + access + "\n" # Remove last comma and space from string and add message
        print(ret)
        self.write_error(ret)    

        return ret
