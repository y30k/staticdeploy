import DownOutlined from "@ant-design/icons/DownOutlined";
import Dropdown from "antd/lib/dropdown";
import Menu from "antd/lib/menu";
import React from "react";

import "./index.css";
import Item from "./Item";

interface IProps {
    actions: React.ReactNode[];
}

function getKey(node: React.ReactNode, fallback: number) {
    return React.isValidElement(node) && node.key !== null
        ? node.key
        : fallback;
}

export default class OperationsDropdown extends React.Component<IProps> {
    static Item = Item;
    renderMenu() {
        return (
            <Menu className="c-OperationsDropdown-menu">
                {this.props.actions.map((action, index) => (
                    <Menu.Item key={getKey(action, index)}>{action}</Menu.Item>
                ))}
            </Menu>
        );
    }
    render() {
        return (
            <Dropdown
                overlay={this.renderMenu()}
                trigger={["click"]}
                placement="bottomRight"
            >
                <a className="c-OperationsDropdown-link ant-dropdown-link">
                    {"Actions "}
                    <DownOutlined />
                </a>
            </Dropdown>
        );
    }
}
