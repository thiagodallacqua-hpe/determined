import { FileOutlined, LeftOutlined } from '@ant-design/icons';
import { Button, Tree } from 'antd';
import { DataNode } from 'antd/lib/tree';
import classNames from 'classnames';
import yaml from 'js-yaml';
import React, { useEffect, useState } from 'react';

import MonacoEditor from 'components/MonacoEditor';
import Section from 'components/Section';
import useRecize from 'hooks/useResize';
import { getExperimentFileFromTree, getExperimentFileTree } from 'services/api';
import { FileNode } from 'services/api-ts-sdk';
import Icon from 'shared/components/Icon';
import Spinner from 'shared/components/Spinner';
import { RawJson } from 'shared/types';

const { DirectoryTree } = Tree;

import css from './CodeViewer.module.scss';
import './index.scss';

export type Props = {
  configRaw?: RawJson;
  experimentId: number;
}

const CodeViewer: React.FC<Props> = ({ experimentId, configRaw }) => {
  const [ config ] = useState(() => {
    /**
   * strip registry_auth from config for display
   * as well as workspace/project names
   */
    if (configRaw) {
      const {
        environment: { registry_auth, ...restEnvironment },
        workspace,
        project,
        ...restConfig
      } = configRaw;
      return { environment: restEnvironment, ...restConfig };
    }
  });
  const { width: documentWidth } = useRecize();

  const [ fileData, setFileData ] = useState<string>();
  const [ files, setFiles ] = useState<FileNode[]>([]);
  const [ fileTree, setFileTree ] = useState<DataNode[]>([]);
  const [ treeMap ] = useState(() => new Map<string, string>());
  const [ isFetching, setIsFetching ] = useState(false);
  const [ fileDir, setFileDir ] = useState('');
  const [ fileName, setFileName ] = useState('');
  const [ viewMode, setViewMode ] = useState<'tree' | 'editor' | undefined>(
    () => documentWidth <= 1024 ? 'tree' : undefined,
  );

  const treeClasses = classNames({
    [ css.hideElement ]:
    (documentWidth <= 1024) && (viewMode === 'editor'),
  });
  const editorClasses = classNames({
    [ css.hideElement ]:
    (documentWidth <= 1024) && (viewMode === 'tree'),
  });

  // get the file tree from backend
  useEffect(() => {
    (async () => {
      const files = await getExperimentFileTree({ experimentId });

      setFiles(files);
    })();
    return () => {
      setFiles([]);
    };
  }, [ experimentId ]);

  // map the file tree
  useEffect(() => {
    const navigateTree = (node: FileNode, key: string): DataNode => {
      treeMap.set(key, node.path);

      const newNode: DataNode = {
        className: 'treeNode',
        isLeaf: true,
        key,
        title: node.name,
      };

      if (node.files?.length) {
        newNode.children = node.files.map((chNode, idx) => navigateTree(chNode, `${key}-${idx}`));
        newNode.isLeaf = false;
      }

      return newNode;
    };
    if (config) {
      setFileTree([
        {
          className: 'treeNode',
          isLeaf: true,
          key: '0-0',
          title: 'Configuration',
        },
        ...files.map<DataNode>((node, idx) => navigateTree(node, `0-${idx + 1}`)),
      ]);

      setFileName('Configuration');
      setFileDir('Configuration');
      setFileData(yaml.dump(config));

      if (documentWidth <= 1024) {
        setViewMode('editor');
      }
    } else {
      setFileTree(files.map<DataNode>((node, idx) => navigateTree(node, `0-${idx}`)));
    }
  }, [ treeMap, files, config, documentWidth ]);

  const onSelectFile = async (
    keys: React.Key[],
    info: { [key:string]: unknown, node: DataNode },
  ) => {
    if (info.node.title === 'Configuration') {
      setFileName('Configuration');
      setFileDir('Configuration');
      setFileData(yaml.dump(config));

      return;
    }

    const filePath = treeMap.get(String(keys[0])) as string;

    if (filePath.includes('.')) { // check if the selected node is a file
      setIsFetching(true);

      try {
        const file = await getExperimentFileFromTree({ experimentId, filePath });

        setIsFetching(false);
        setFileData(decodeURIComponent(escape(window.atob(file))));
        setFileDir(filePath);
        setFileName(info.node.title as string);

        if (documentWidth <= 1024) {
          setViewMode('editor');
        }
      } catch (error) {
        setIsFetching(false);

        throw new Error(error as string);
      }
    }
  };

  const setEditorLanguageSyntax = () => {
    const fileExt = fileDir.split('.')[1];

    if (fileExt === 'js') {
      return 'javascript';
    }

    if (fileExt === 'py') {
      return 'python';
    }

    if (fileExt === 'ts') {
      return 'typescript';
    }

    return fileExt;
  };

  return (
    <section className={css.base}>
      <Section className={treeClasses} id="fileTree">
        <DirectoryTree
          className={css.fileTree}
          data-testid="fileTree"
          defaultExpandAll
          defaultSelectedKeys={(config && documentWidth > 1024) ? [ '0-0' ] : undefined}
          treeData={fileTree}
          onSelect={onSelectFile}
        />
      </Section>
      {
        !!fileDir && (
          <Spinner className={editorClasses} spinning={isFetching}>
            <section className={css.fileDir}>
              <div className={css.fileInfo}>
                <div className={css.buttonContainer}>
                  {
                    documentWidth <= 1024 && (
                      <LeftOutlined
                        className={css.leftChevron}
                        onClick={() => setViewMode('tree')}
                      />
                    )
                  }
                  <FileOutlined />
                  <span className={css.filePath}>{fileName}</span>
                </div>
                <div className={css.buttonsContainer}>
                  {/* <Button className={css.noBorderButton}>Open in Notebook</Button>
                  TODO: this will be added in the future*/}
                  {
                    !fileDir.includes('Configuration') && (
                      <Button
                        className={css.noBorderButton}
                        ghost
                        icon={<Icon name="download" size="big" />}
                      />
                    )
                  }
                </div>
              </div>
            </section>
          </Spinner>
        )
      }
      <Section
        bodyNoPadding
        bodyScroll
        className={editorClasses}
        id="editor"
        maxHeight>
        <Spinner spinning={isFetching}>
          {
            !isFetching && !fileData
              ? <h5>Please, choose a file to preview.</h5>
              : (
                <MonacoEditor
                  height="100%"
                  language={setEditorLanguageSyntax()}
                  options={{
                    minimap: {
                      enabled: !!fileData?.length,
                      showSlider: 'mouseover',
                      size: 'fit',
                    },
                    occurrencesHighlight: false,
                    readOnly: true,
                  }}
                  value={fileData}
                />
              )
          }
        </Spinner>
      </Section>
    </section>
  );
};

export default CodeViewer;
