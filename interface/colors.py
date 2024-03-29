class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    @staticmethod
    def make_warning(text) -> str:
        return f"{bcolors.WARNING}{text}{bcolors.ENDC}"

    @staticmethod
    def make_green(text) -> str:
        return f"{bcolors.OKGREEN}{text}{bcolors.ENDC}"