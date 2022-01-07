package jadx.gui.ui.codearea;

import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.List;

import javax.swing.AbstractAction;
import javax.swing.KeyStroke;

import org.jetbrains.annotations.Nullable;

import jadx.api.JavaMethod;
import jadx.core.dex.info.MethodInfo;
import jadx.core.dex.instructions.args.ArgType;
import jadx.gui.treemodel.JNode;
import jadx.gui.utils.UiUtils;
import jadx.gui.treemodel.JMethod;
import static javax.swing.KeyStroke.getKeyStroke;

public final class FridaAction extends JNodeMenuAction<JNode> {
	private static final long serialVersionUID = -1186470538894941302L;

	public FridaAction(CodeArea codeArea) {
		super(("Frida Script"), codeArea);
		KeyStroke key = getKeyStroke(KeyEvent.VK_F, 0);
		codeArea.getInputMap().put(key, "frida copy");
		codeArea.getActionMap().put("frida copy", new AbstractAction() {
			@Override
			public void actionPerformed(ActionEvent e) {
				node = getNodeByOffset(codeArea.getWordStart(codeArea.getCaretPosition()));
				doFrida();
			}
		});
	}

	private static String convertType(String type){
        if (!type.endsWith("[]")) {
            return type;
        }
        String typeResult = "";
        while (type.endsWith("[]")) {
            typeResult += "[";
            type = type.substring(0, type.length()-2);
        }
        switch (type){
            case "int":
                typeResult += "I";
                break;
            case "boolean":
                typeResult += "Z";
                break;
            case "byte":
                typeResult += "B";
                break;
            case "char":
                typeResult += "C";
                break;
            case "double":
                typeResult += "D";
                break;
            case "float":
                typeResult += "F";
                break;
            case "long":
                typeResult += "J";
                break;
            case "short":
                typeResult += "S";
                break;
            default:
                typeResult += "L"+type + ";";
                break;
        }
        return typeResult;
    }
	
	private void doFrida() {
		if (node != null) {
			if (node.getClass().getName().equals(JMethod.class.getName())) {
				JMethod jMethod = (JMethod) node;
				JavaMethod javaMethod = jMethod.getJavaMethod();
				MethodInfo methodInfo = javaMethod.getMethodNode().getMethodInfo();
				String className = methodInfo.getDeclClass().getType().getObject();
				String methodName = methodInfo.getName();
				List<ArgType> argTypes = methodInfo.getArgumentsTypes();
				String arguments = "";
				String params = "";
				for (int i = 0; i < argTypes.size(); i++) {
					ArgType arg = argTypes.get(i);
					arguments = arguments +"'" + convertType(arg.toString()) + "', ";
					params = params +"v"+i + ", ";
				}
				if(arguments.length() > 0) {
					arguments = arguments.substring(0, arguments.length() - 2);
					params = params.substring(0, params.length() -2);
					
				}
				if(methodInfo.isConstructor()){
					methodName = "$init";
				}
				StringBuffer sb = new StringBuffer();
				String classNameVar = className.replace("$","_");
				classNameVar = classNameVar.replace("-","_");
				classNameVar = classNameVar.replace(".","_");
				classNameVar += "_cls";
				sb.append("var ");
				sb.append(classNameVar);
				sb.append(" = Java.use('");
				sb.append(className);
				sb.append("');\n");
				sb.append(classNameVar);
				sb.append(".");
				sb.append(methodName);
				sb.append(".overload(");
				sb.append(arguments);
				sb.append(").implementation = function(");
				sb.append(params);
				sb.append(") {\n    let invokeId = INVOKEID++;\n    ");
				if(methodInfo.isConstructor() == false && methodInfo.getReturnType().isVoid() == false) {
					sb.append("var ret = ");
				}
				sb.append("this.");
				sb.append(methodName);
				sb.append("(");
				sb.append(params);
				sb.append(");\n    printMethod(invokeId, false, false, arguments, ret ,'");
				sb.append(methodInfo.toString());
				sb.append("');\n");
				if(methodInfo.isConstructor() == false && methodInfo.getReturnType().isVoid() == false) {
					sb.append("    return ret;\n");
				}
				sb.append("}");
				System.out.println(sb.toString());
				UiUtils.setClipboardString(sb.toString());
			}
			node = null;
		}
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		doFrida();
	}

	@Nullable
	@Override
	public JNode getNodeByOffset(int offset) {
		return codeArea.getJNodeAtOffset(offset);
	}
}
