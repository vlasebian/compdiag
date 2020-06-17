import os
import subprocess

from compdiag.uml.util import nl

PLANT_UML_JAR = '/usr/local/bin/plantuml.jar'

class UMLDiagram():
    """ 
    Base class for UML Diagram classes. Diagrams are written using PlantUML
    language and generated using plantuml.jar (Java installation is required).

    You can download plantuml.jar from here: https://plantuml.com/download.
    Place the plantuml.jar file in your /usr/local/bin directory.

    More on PlantUML diagrams can be found at:
        https://plantuml.com/
    """

    def __init__(self):
        # Diagram source. PlantUML statements are appended to this string. 
        self.__uml = ''

        # General diagram properties. Specific ones should be specified in
        # concrete classes that implement this interface. All values should
        # be strings.
        self.__properties = {
            #'scale': '1.5',
            #'scale': '1024 width',
            #'scale': '768 height',
        }

        # General style statements. Same rules as above.
        self.__skinparam = {
            'shadowing': 'False',
            #'defaultFontName': 'Courier',
        }

    def get_source(self):
        """
        Append properties, style, start and end statements. Returns complete
        source for generating the diagram.
        """

        uml_text = ''

        uml_text += nl('@startuml')
        uml_text += nl(self.__get_configuration())
        uml_text += nl(self.__uml)
        uml_text += nl('@enduml')

        return uml_text

    def __get_configuration(self):
        """
        Converts the properties and style dictionaries to PlantUML
        statements. Returns a string.
        """
        configuration = ''

        for key, value in self.__properties.items():
            if value: configuration += nl(key + ' ' + value)
        
        for key, value in self.__skinparam.items():
            if value: configuration += nl('skinparam' + ' ' + key + ' ' + value)

        return configuration

    def add_skinparam_options(self, options):
        for key, value in options.items():
            self.__skinparam[key] = value

    def add_properties(self, properties):
        for key, value in properties.items():
            self.__properties[key] = value

    def set_title(self, title):
        """ Set diagram title. """

        self.__properties['title'] = title
    
    def add_raw_uml(self, line):
        self.__uml += nl(line)

    def uml_statement(statement):
        """ 
        Decorator used for defining methods that represent a PlantUML
        statement. Appends the statement to diagram source.
        """
        def uml_command_decorator(self, *args, **kwargs):
            line = statement(self, *args, **kwargs)
            if line:
                self.__uml += nl(line)
        return uml_command_decorator

    def create_diagram(self, output_filename = 'out', output_format = 'png'):
        """
        Create a diagram by calling plantuml.jar. Returns True on success, else
        False.

        output_filename  -- output image filename
        output_format    -- output image format


        Some available output fromats:
        'png', 'svg', 'eps', 'pdf', 'vdx', 'txt', 'utxt'

        More formats can be found in plantuml.jar help:
        java -jar plantuml.jar -h

        """
        out_dir = os.getcwd() + '/'

        ret = subprocess.run([
            'java', '-jar', PLANT_UML_JAR,
            '-o', out_dir,
            '-t' + output_format,
            '-nbthread auto',
            '-DPLANTUML_LIMIT_SIZE=8192',
            '-pipe',
            ],
            stdout=subprocess.PIPE,
            input=bytes(self.get_source(), encoding='utf-8'),
            check=True
            )

        if ret.returncode != 0:
            return False

        with open(output_filename + '.' + output_format, 'wb') as f:
            f.write(ret.stdout)

