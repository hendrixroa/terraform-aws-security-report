const axios = require('axios');
const AWS = require('aws-sdk');
const FunctionShield = require('@puresec/function-shield');
const logger = require('pino')();

const ENV = process.env;
const region = ENV.AWS_REGION;
const slackInfraAlertBot = ENV.slack_infra_alert_bot;

FunctionShield.configure(
    {
        policy: {
            read_write_tmp: 'alert',
            create_child_process: 'alert',
            outbound_connectivity: 'alert',
            read_handler: 'alert'
        },
        disable_analytics: false,
        token: ENV.function_shield_token
    });

exports.handler = async (event, context, callback) => {
    context.callbackWaitsForEmptyEventLoop = false;

    let dataFinding;
    const data = JSON.parse(JSON.stringify(event));
    const linkConfig = `https://${region}.console.aws.amazon.com/config/home?region=${region}&v2=true#/rules?filter=NON_COMPLIANT`;

    switch (data['detail-type']) {
        case 'Config Rules Compliance Change':
            if(data.detail.newEvaluationResult.complianceType === 'NON_COMPLIANT') {
                logger.info('From aws config: ', JSON.stringify(data.detail));
                dataFinding = {
                    service: 'AWS Config Rules',
                    title: `The ${data.detail.newEvaluationResult.evaluationResultIdentifier.evaluationResultQualifier.configRuleName} rule is violated`,
                    resource: data.detail.newEvaluationResult.evaluationResultIdentifier.evaluationResultQualifier.resourceId,
                    link: linkConfig,
                };
            }
            break;
        case 'Config Rules Re-evaluation Status':
            if(data.detail.newEvaluationResult.complianceType === 'NON_COMPLIANT') {
                logger.info('From aws config: ', JSON.stringify(data.detail));
                dataFinding = {
                    service: 'AWS Config Rules',
                    title: `The ${data.detail.newEvaluationResult.evaluationResultIdentifier.evaluationResultQualifier.configRuleName} rule is violated`,
                    resource: data.detail.newEvaluationResult.evaluationResultIdentifier.evaluationResultQualifier.resourceId,
                    link: linkConfig,
                };
            }
            break;
        case 'GuardDuty Finding':
            if(Number(data.detail.severity) > 0) {
                logger.info('From guardduty: ', JSON.stringify(data.detail));
                dataFinding = {
                    service: 'AWS GuardDuty',
                    title: data.detail.title,
                    resource: data.detail.resource.resourceType,
                    link: `https://${region}.console.aws.amazon.com/guardduty/home?region=${region}#/findings?macros=current`,
                }
            }
            break;
    }

    if(!dataFinding) {
        return context.succeed();
    }

    const resultStage = await getStage();

    const postData = {
        channel: `cicd-${resultStage.stage}`,
        icon_emoji: ':warning:',
        username: 'AWS Security Alerts',
        attachments: [
            {
                author_name: dataFinding.service,
                color: resultStage.color,
                text: `${dataFinding.title} (<${dataFinding.link}|More details>)`,
                mrkdwn_in: ['text']
            }
        ],
        mrkdwn: true
    };

    const options = {
        method: 'post',
        url: `https://slack.com/api/chat.postMessage`,
        data: postData,
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${slackInfraAlertBot}`
        }
    };

    try {
        await doRequest(options);
        return context.succeed();
    } catch (error) {
        logger.error('Error to send alerts: ', error.response, error.response.data);
        return context.fail();
    }
};

async function doRequest(options) {
    return axios(options);
}

async function getStage(){
    const iam = new AWS.IAM();
    const result = await iam.listAccountAliases({}).promise();
    return result.AccountAliases[0].includes('production') ? { stage: 'pro', color: '#ff0000' } : { stage: 'staging', color: '#ffc76d' };
}
