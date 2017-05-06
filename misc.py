from xml.dom.minidom import parseString
from re import sub


# NOT SECURE IN ANY WAY.
# will have a lot of warnings because of setattr.

class XmlObject(object):
    def __init__(self, name, text_nodes=None, dom_obj=None, **children):
        self.name = name
        self.text_nodes = text_nodes
        for child in children:
            setattr(self, child, children[child])
        self._dom_obj = dom_obj
        self._child_nodes = children

    @classmethod
    def parse_xml(cls, data):
        return cls.dom_to_xml_object(parseString(data))

    @classmethod
    def dom_to_xml_object(cls, dom):
        child_nodes = dom.childNodes

        xml_children = {}

        data_nodes = []
        for node in child_nodes:
            if node.nodeType == dom.ELEMENT_NODE:
                if node.nodeName in xml_children.keys():
                    xml_children[node.nodeName.lower()] += (cls.dom_to_xml_object(node),)
                xml_children[camel_case_to_snake_case(node.nodeName)] = cls.dom_to_xml_object(node)
            if node.nodeType == dom.TEXT_NODE:
                data_nodes.append(node)

        # if there is only 1 item, make the object itself the item instead of the list.
        if len(data_nodes) == 1:
            data_nodes = data_nodes[0]

        return XmlObject(dom.nodeName, data_nodes, dom, **xml_children)


class ObjectAttributeSetter(object):
    """
        a class for setting attributes on a single object for the pleasing eye.
        for example:
            let's say i have to return 3 objects, not i don't want the consumer will have to look on
            each object like a list, instead he will look at it as an object.
            so if a list has [my_name, my_family, my_age]
            you will do it as
            obj.my_name
            obj.my_family
            obj.my_age


    """

    def __init__(self, **attributes):
        for attribute in attributes:
            setattr(self, attribute, attributes[attribute])


def camel_case_to_snake_case(name):
    s1 = sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()
