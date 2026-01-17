
// Description: Java 25 in-memory RAM DbIO implementation for SecUser.

/*
 *	io.github.msobkow.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	This file is part of Mark's Code Fractal CFSec.
 *	
 *	Mark's Code Fractal CFSec is available under dual commercial license from
 *	Mark Stephen Sobkow, or under the terms of the GNU Library General Public License,
 *	Version 3 or later.
 *	
 *	Mark's Code Fractal CFSec is free software: you can redistribute it and/or
 *	modify it under the terms of the GNU Library General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *	
 *	Mark's Code Fractal CFSec is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU Library General Public License
 *	along with Mark's Code Fractal CFSec.  If not, see <https://www.gnu.org/licenses/>.
 *	
 *	If you wish to modify and use this code without publishing your changes in order to
 *	tie it to proprietary code, please contact Mark Stephen Sobkow
 *	for a commercial license at mark.sobkow@gmail.com
 *	
 */

package io.github.msobkow.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import io.github.msobkow.v3_1.cflib.*;
import io.github.msobkow.v3_1.cflib.dbutil.*;

import io.github.msobkow.v3_1.cfsec.cfsec.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamSecUserTable in-memory RAM DbIO implementation
 *	for SecUser.
 */
public class CFSecRamSecUserTable
	implements ICFSecSecUserTable
{
	private ICFSecSchema schema;
	private Map< CFSecSecUserPKey,
				CFSecSecUserBuff > dictByPKey
		= new HashMap< CFSecSecUserPKey,
				CFSecSecUserBuff >();
	private Map< CFSecSecUserByULoginIdxKey,
			CFSecSecUserBuff > dictByULoginIdx
		= new HashMap< CFSecSecUserByULoginIdxKey,
			CFSecSecUserBuff >();
	private Map< CFSecSecUserByEMConfIdxKey,
				Map< CFSecSecUserPKey,
					CFSecSecUserBuff >> dictByEMConfIdx
		= new HashMap< CFSecSecUserByEMConfIdxKey,
				Map< CFSecSecUserPKey,
					CFSecSecUserBuff >>();
	private Map< CFSecSecUserByPwdResetIdxKey,
				Map< CFSecSecUserPKey,
					CFSecSecUserBuff >> dictByPwdResetIdx
		= new HashMap< CFSecSecUserByPwdResetIdxKey,
				Map< CFSecSecUserPKey,
					CFSecSecUserBuff >>();
	private Map< CFSecSecUserByDefDevIdxKey,
				Map< CFSecSecUserPKey,
					CFSecSecUserBuff >> dictByDefDevIdx
		= new HashMap< CFSecSecUserByDefDevIdxKey,
				Map< CFSecSecUserPKey,
					CFSecSecUserBuff >>();

	public CFSecRamSecUserTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public void createSecUser( CFSecAuthorization Authorization,
		CFSecSecUserBuff Buff )
	{
		final String S_ProcName = "createSecUser";
		CFSecSecUserPKey pkey = schema.getFactorySecUser().newPKey();
		pkey.setRequiredSecUserId( schema.nextSecUserIdGen() );
		Buff.setRequiredSecUserId( pkey.getRequiredSecUserId() );
		CFSecSecUserByULoginIdxKey keyULoginIdx = schema.getFactorySecUser().newULoginIdxKey();
		keyULoginIdx.setRequiredLoginId( Buff.getRequiredLoginId() );

		CFSecSecUserByEMConfIdxKey keyEMConfIdx = schema.getFactorySecUser().newEMConfIdxKey();
		keyEMConfIdx.setOptionalEMailConfirmUuid6( Buff.getOptionalEMailConfirmUuid6() );

		CFSecSecUserByPwdResetIdxKey keyPwdResetIdx = schema.getFactorySecUser().newPwdResetIdxKey();
		keyPwdResetIdx.setOptionalPasswordResetUuid6( Buff.getOptionalPasswordResetUuid6() );

		CFSecSecUserByDefDevIdxKey keyDefDevIdx = schema.getFactorySecUser().newDefDevIdxKey();
		keyDefDevIdx.setOptionalDfltDevUserId( Buff.getOptionalDfltDevUserId() );
		keyDefDevIdx.setOptionalDfltDevName( Buff.getOptionalDfltDevName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByULoginIdx.containsKey( keyULoginIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecUserLoginIdx",
				keyULoginIdx );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		dictByULoginIdx.put( keyULoginIdx, Buff );

		Map< CFSecSecUserPKey, CFSecSecUserBuff > subdictEMConfIdx;
		if( dictByEMConfIdx.containsKey( keyEMConfIdx ) ) {
			subdictEMConfIdx = dictByEMConfIdx.get( keyEMConfIdx );
		}
		else {
			subdictEMConfIdx = new HashMap< CFSecSecUserPKey, CFSecSecUserBuff >();
			dictByEMConfIdx.put( keyEMConfIdx, subdictEMConfIdx );
		}
		subdictEMConfIdx.put( pkey, Buff );

		Map< CFSecSecUserPKey, CFSecSecUserBuff > subdictPwdResetIdx;
		if( dictByPwdResetIdx.containsKey( keyPwdResetIdx ) ) {
			subdictPwdResetIdx = dictByPwdResetIdx.get( keyPwdResetIdx );
		}
		else {
			subdictPwdResetIdx = new HashMap< CFSecSecUserPKey, CFSecSecUserBuff >();
			dictByPwdResetIdx.put( keyPwdResetIdx, subdictPwdResetIdx );
		}
		subdictPwdResetIdx.put( pkey, Buff );

		Map< CFSecSecUserPKey, CFSecSecUserBuff > subdictDefDevIdx;
		if( dictByDefDevIdx.containsKey( keyDefDevIdx ) ) {
			subdictDefDevIdx = dictByDefDevIdx.get( keyDefDevIdx );
		}
		else {
			subdictDefDevIdx = new HashMap< CFSecSecUserPKey, CFSecSecUserBuff >();
			dictByDefDevIdx.put( keyDefDevIdx, subdictDefDevIdx );
		}
		subdictDefDevIdx.put( pkey, Buff );

	}

	public CFSecSecUserBuff readDerived( CFSecAuthorization Authorization,
		CFSecSecUserPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecUser.readDerived";
		CFSecSecUserPKey key = schema.getFactorySecUser().newPKey();
		key.setRequiredSecUserId( PKey.getRequiredSecUserId() );
		CFSecSecUserBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecUserBuff lockDerived( CFSecAuthorization Authorization,
		CFSecSecUserPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecUser.readDerived";
		CFSecSecUserPKey key = schema.getFactorySecUser().newPKey();
		key.setRequiredSecUserId( PKey.getRequiredSecUserId() );
		CFSecSecUserBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecUserBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecUser.readAllDerived";
		CFSecSecUserBuff[] retList = new CFSecSecUserBuff[ dictByPKey.values().size() ];
		Iterator< CFSecSecUserBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFSecSecUserBuff readDerivedByULoginIdx( CFSecAuthorization Authorization,
		String LoginId )
	{
		final String S_ProcName = "CFSecRamSecUser.readDerivedByULoginIdx";
		CFSecSecUserByULoginIdxKey key = schema.getFactorySecUser().newULoginIdxKey();
		key.setRequiredLoginId( LoginId );

		CFSecSecUserBuff buff;
		if( dictByULoginIdx.containsKey( key ) ) {
			buff = dictByULoginIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecUserBuff[] readDerivedByEMConfIdx( CFSecAuthorization Authorization,
		CFLibUuid6 EMailConfirmUuid6 )
	{
		final String S_ProcName = "CFSecRamSecUser.readDerivedByEMConfIdx";
		CFSecSecUserByEMConfIdxKey key = schema.getFactorySecUser().newEMConfIdxKey();
		key.setOptionalEMailConfirmUuid6( EMailConfirmUuid6 );

		CFSecSecUserBuff[] recArray;
		if( dictByEMConfIdx.containsKey( key ) ) {
			Map< CFSecSecUserPKey, CFSecSecUserBuff > subdictEMConfIdx
				= dictByEMConfIdx.get( key );
			recArray = new CFSecSecUserBuff[ subdictEMConfIdx.size() ];
			Iterator< CFSecSecUserBuff > iter = subdictEMConfIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSecUserPKey, CFSecSecUserBuff > subdictEMConfIdx
				= new HashMap< CFSecSecUserPKey, CFSecSecUserBuff >();
			dictByEMConfIdx.put( key, subdictEMConfIdx );
			recArray = new CFSecSecUserBuff[0];
		}
		return( recArray );
	}

	public CFSecSecUserBuff[] readDerivedByPwdResetIdx( CFSecAuthorization Authorization,
		CFLibUuid6 PasswordResetUuid6 )
	{
		final String S_ProcName = "CFSecRamSecUser.readDerivedByPwdResetIdx";
		CFSecSecUserByPwdResetIdxKey key = schema.getFactorySecUser().newPwdResetIdxKey();
		key.setOptionalPasswordResetUuid6( PasswordResetUuid6 );

		CFSecSecUserBuff[] recArray;
		if( dictByPwdResetIdx.containsKey( key ) ) {
			Map< CFSecSecUserPKey, CFSecSecUserBuff > subdictPwdResetIdx
				= dictByPwdResetIdx.get( key );
			recArray = new CFSecSecUserBuff[ subdictPwdResetIdx.size() ];
			Iterator< CFSecSecUserBuff > iter = subdictPwdResetIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSecUserPKey, CFSecSecUserBuff > subdictPwdResetIdx
				= new HashMap< CFSecSecUserPKey, CFSecSecUserBuff >();
			dictByPwdResetIdx.put( key, subdictPwdResetIdx );
			recArray = new CFSecSecUserBuff[0];
		}
		return( recArray );
	}

	public CFSecSecUserBuff[] readDerivedByDefDevIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 DfltDevUserId,
		String DfltDevName )
	{
		final String S_ProcName = "CFSecRamSecUser.readDerivedByDefDevIdx";
		CFSecSecUserByDefDevIdxKey key = schema.getFactorySecUser().newDefDevIdxKey();
		key.setOptionalDfltDevUserId( DfltDevUserId );
		key.setOptionalDfltDevName( DfltDevName );

		CFSecSecUserBuff[] recArray;
		if( dictByDefDevIdx.containsKey( key ) ) {
			Map< CFSecSecUserPKey, CFSecSecUserBuff > subdictDefDevIdx
				= dictByDefDevIdx.get( key );
			recArray = new CFSecSecUserBuff[ subdictDefDevIdx.size() ];
			Iterator< CFSecSecUserBuff > iter = subdictDefDevIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSecUserPKey, CFSecSecUserBuff > subdictDefDevIdx
				= new HashMap< CFSecSecUserPKey, CFSecSecUserBuff >();
			dictByDefDevIdx.put( key, subdictDefDevIdx );
			recArray = new CFSecSecUserBuff[0];
		}
		return( recArray );
	}

	public CFSecSecUserBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecUser.readDerivedByIdIdx() ";
		CFSecSecUserPKey key = schema.getFactorySecUser().newPKey();
		key.setRequiredSecUserId( SecUserId );

		CFSecSecUserBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecUserBuff readBuff( CFSecAuthorization Authorization,
		CFSecSecUserPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecUser.readBuff";
		CFSecSecUserBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a011" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecUserBuff lockBuff( CFSecAuthorization Authorization,
		CFSecSecUserPKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFSecSecUserBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a011" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecUserBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecUser.readAllBuff";
		CFSecSecUserBuff buff;
		ArrayList<CFSecSecUserBuff> filteredList = new ArrayList<CFSecSecUserBuff>();
		CFSecSecUserBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a011" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFSecSecUserBuff[0] ) );
	}

	/**
	 *	Read a page of all the specific SecUser buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecUser instances in the database accessible for the Authorization.
	 */
	public CFSecSecUserBuff[] pageAllBuff( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageAllBuff";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public CFSecSecUserBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecUser.readBuffByIdIdx() ";
		CFSecSecUserBuff buff = readDerivedByIdIdx( Authorization,
			SecUserId );
		if( ( buff != null ) && buff.getClassCode().equals( "a011" ) ) {
			return( (CFSecSecUserBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecSecUserBuff readBuffByULoginIdx( CFSecAuthorization Authorization,
		String LoginId )
	{
		final String S_ProcName = "CFSecRamSecUser.readBuffByULoginIdx() ";
		CFSecSecUserBuff buff = readDerivedByULoginIdx( Authorization,
			LoginId );
		if( ( buff != null ) && buff.getClassCode().equals( "a011" ) ) {
			return( (CFSecSecUserBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecSecUserBuff[] readBuffByEMConfIdx( CFSecAuthorization Authorization,
		CFLibUuid6 EMailConfirmUuid6 )
	{
		final String S_ProcName = "CFSecRamSecUser.readBuffByEMConfIdx() ";
		CFSecSecUserBuff buff;
		ArrayList<CFSecSecUserBuff> filteredList = new ArrayList<CFSecSecUserBuff>();
		CFSecSecUserBuff[] buffList = readDerivedByEMConfIdx( Authorization,
			EMailConfirmUuid6 );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a011" ) ) {
				filteredList.add( (CFSecSecUserBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSecUserBuff[0] ) );
	}

	public CFSecSecUserBuff[] readBuffByPwdResetIdx( CFSecAuthorization Authorization,
		CFLibUuid6 PasswordResetUuid6 )
	{
		final String S_ProcName = "CFSecRamSecUser.readBuffByPwdResetIdx() ";
		CFSecSecUserBuff buff;
		ArrayList<CFSecSecUserBuff> filteredList = new ArrayList<CFSecSecUserBuff>();
		CFSecSecUserBuff[] buffList = readDerivedByPwdResetIdx( Authorization,
			PasswordResetUuid6 );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a011" ) ) {
				filteredList.add( (CFSecSecUserBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSecUserBuff[0] ) );
	}

	public CFSecSecUserBuff[] readBuffByDefDevIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 DfltDevUserId,
		String DfltDevName )
	{
		final String S_ProcName = "CFSecRamSecUser.readBuffByDefDevIdx() ";
		CFSecSecUserBuff buff;
		ArrayList<CFSecSecUserBuff> filteredList = new ArrayList<CFSecSecUserBuff>();
		CFSecSecUserBuff[] buffList = readDerivedByDefDevIdx( Authorization,
			DfltDevUserId,
			DfltDevName );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a011" ) ) {
				filteredList.add( (CFSecSecUserBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSecUserBuff[0] ) );
	}

	/**
	 *	Read a page array of the specific SecUser buffer instances identified by the duplicate key EMConfIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	EMailConfirmUuid6	The SecUser key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecSecUserBuff[] pageBuffByEMConfIdx( CFSecAuthorization Authorization,
		CFLibUuid6 EMailConfirmUuid6,
		CFLibDbKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageBuffByEMConfIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecUser buffer instances identified by the duplicate key PwdResetIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PasswordResetUuid6	The SecUser key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecSecUserBuff[] pageBuffByPwdResetIdx( CFSecAuthorization Authorization,
		CFLibUuid6 PasswordResetUuid6,
		CFLibDbKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageBuffByPwdResetIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecUser buffer instances identified by the duplicate key DefDevIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	DfltDevUserId	The SecUser key attribute of the instance generating the id.
	 *
	 *	@param	DfltDevName	The SecUser key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecSecUserBuff[] pageBuffByDefDevIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 DfltDevUserId,
		String DfltDevName,
		CFLibDbKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageBuffByDefDevIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public void updateSecUser( CFSecAuthorization Authorization,
		CFSecSecUserBuff Buff )
	{
		CFSecSecUserPKey pkey = schema.getFactorySecUser().newPKey();
		pkey.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		CFSecSecUserBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecUser",
				"Existing record not found",
				"SecUser",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecUser",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecSecUserByULoginIdxKey existingKeyULoginIdx = schema.getFactorySecUser().newULoginIdxKey();
		existingKeyULoginIdx.setRequiredLoginId( existing.getRequiredLoginId() );

		CFSecSecUserByULoginIdxKey newKeyULoginIdx = schema.getFactorySecUser().newULoginIdxKey();
		newKeyULoginIdx.setRequiredLoginId( Buff.getRequiredLoginId() );

		CFSecSecUserByEMConfIdxKey existingKeyEMConfIdx = schema.getFactorySecUser().newEMConfIdxKey();
		existingKeyEMConfIdx.setOptionalEMailConfirmUuid6( existing.getOptionalEMailConfirmUuid6() );

		CFSecSecUserByEMConfIdxKey newKeyEMConfIdx = schema.getFactorySecUser().newEMConfIdxKey();
		newKeyEMConfIdx.setOptionalEMailConfirmUuid6( Buff.getOptionalEMailConfirmUuid6() );

		CFSecSecUserByPwdResetIdxKey existingKeyPwdResetIdx = schema.getFactorySecUser().newPwdResetIdxKey();
		existingKeyPwdResetIdx.setOptionalPasswordResetUuid6( existing.getOptionalPasswordResetUuid6() );

		CFSecSecUserByPwdResetIdxKey newKeyPwdResetIdx = schema.getFactorySecUser().newPwdResetIdxKey();
		newKeyPwdResetIdx.setOptionalPasswordResetUuid6( Buff.getOptionalPasswordResetUuid6() );

		CFSecSecUserByDefDevIdxKey existingKeyDefDevIdx = schema.getFactorySecUser().newDefDevIdxKey();
		existingKeyDefDevIdx.setOptionalDfltDevUserId( existing.getOptionalDfltDevUserId() );
		existingKeyDefDevIdx.setOptionalDfltDevName( existing.getOptionalDfltDevName() );

		CFSecSecUserByDefDevIdxKey newKeyDefDevIdx = schema.getFactorySecUser().newDefDevIdxKey();
		newKeyDefDevIdx.setOptionalDfltDevUserId( Buff.getOptionalDfltDevUserId() );
		newKeyDefDevIdx.setOptionalDfltDevName( Buff.getOptionalDfltDevName() );

		// Check unique indexes

		if( ! existingKeyULoginIdx.equals( newKeyULoginIdx ) ) {
			if( dictByULoginIdx.containsKey( newKeyULoginIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecUser",
					"SecUserLoginIdx",
					newKeyULoginIdx );
			}
		}

		// Validate foreign keys

		// Update is valid

		Map< CFSecSecUserPKey, CFSecSecUserBuff > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		dictByULoginIdx.remove( existingKeyULoginIdx );
		dictByULoginIdx.put( newKeyULoginIdx, Buff );

		subdict = dictByEMConfIdx.get( existingKeyEMConfIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByEMConfIdx.containsKey( newKeyEMConfIdx ) ) {
			subdict = dictByEMConfIdx.get( newKeyEMConfIdx );
		}
		else {
			subdict = new HashMap< CFSecSecUserPKey, CFSecSecUserBuff >();
			dictByEMConfIdx.put( newKeyEMConfIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByPwdResetIdx.get( existingKeyPwdResetIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByPwdResetIdx.containsKey( newKeyPwdResetIdx ) ) {
			subdict = dictByPwdResetIdx.get( newKeyPwdResetIdx );
		}
		else {
			subdict = new HashMap< CFSecSecUserPKey, CFSecSecUserBuff >();
			dictByPwdResetIdx.put( newKeyPwdResetIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByDefDevIdx.get( existingKeyDefDevIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByDefDevIdx.containsKey( newKeyDefDevIdx ) ) {
			subdict = dictByDefDevIdx.get( newKeyDefDevIdx );
		}
		else {
			subdict = new HashMap< CFSecSecUserPKey, CFSecSecUserBuff >();
			dictByDefDevIdx.put( newKeyDefDevIdx, subdict );
		}
		subdict.put( pkey, Buff );

	}

	public void deleteSecUser( CFSecAuthorization Authorization,
		CFSecSecUserBuff Buff )
	{
		final String S_ProcName = "CFSecRamSecUserTable.deleteSecUser() ";
		String classCode;
		CFSecSecUserPKey pkey = schema.getFactorySecUser().newPKey();
		pkey.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		CFSecSecUserBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecUser",
				pkey );
		}
					{
						CFSecSecUserBuff editBuff = schema.getTableSecUser().readDerivedByIdIdx( Authorization,
						existing.getRequiredSecUserId() );
						editBuff.setOptionalDfltDevUserId( null );
						editBuff.setOptionalDfltDevName( null );
						classCode = editBuff.getClassCode();
						if( classCode.equals( "a011" ) ) {
							schema.getTableSecUser().updateSecUser( Authorization, editBuff );
						}
						else {
							new CFLibUnsupportedClassException( getClass(),
								S_ProcName,
								"Unrecognized ClassCode \"" + classCode + "\"" );
						}
					}
		CFSecSecUserBuff editSubobj = schema.getTableSecUser().readDerivedByIdIdx( Authorization,
			existing.getRequiredSecUserId() );
			editSubobj.setOptionalDfltDevUserId( null );
			editSubobj.setOptionalDfltDevName( null );
		classCode = editSubobj.getClassCode();
		if( classCode.equals( "a011" ) ) {
			schema.getTableSecUser().updateSecUser( Authorization, editSubobj );
		}
		else {
			new CFLibUnsupportedClassException( getClass(),
				S_ProcName,
				"Unrecognized ClassCode \"" + classCode + "\"" );
		}
		existing = editSubobj;
					schema.getTableTSecGrpMemb().deleteTSecGrpMembByUserIdx( Authorization,
						existing.getRequiredSecUserId() );
					schema.getTableSecGrpMemb().deleteSecGrpMembByUserIdx( Authorization,
						existing.getRequiredSecUserId() );
					schema.getTableSecSession().deleteSecSessionBySecUserIdx( Authorization,
						existing.getRequiredSecUserId() );
					schema.getTableSecSession().deleteSecSessionBySecProxyIdx( Authorization,
						existing.getRequiredSecUserId() );
					schema.getTableSecDevice().deleteSecDeviceByUserIdx( Authorization,
						existing.getRequiredSecUserId() );
		CFSecSecUserByULoginIdxKey keyULoginIdx = schema.getFactorySecUser().newULoginIdxKey();
		keyULoginIdx.setRequiredLoginId( existing.getRequiredLoginId() );

		CFSecSecUserByEMConfIdxKey keyEMConfIdx = schema.getFactorySecUser().newEMConfIdxKey();
		keyEMConfIdx.setOptionalEMailConfirmUuid6( existing.getOptionalEMailConfirmUuid6() );

		CFSecSecUserByPwdResetIdxKey keyPwdResetIdx = schema.getFactorySecUser().newPwdResetIdxKey();
		keyPwdResetIdx.setOptionalPasswordResetUuid6( existing.getOptionalPasswordResetUuid6() );

		CFSecSecUserByDefDevIdxKey keyDefDevIdx = schema.getFactorySecUser().newDefDevIdxKey();
		keyDefDevIdx.setOptionalDfltDevUserId( existing.getOptionalDfltDevUserId() );
		keyDefDevIdx.setOptionalDfltDevName( existing.getOptionalDfltDevName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecSecUserPKey, CFSecSecUserBuff > subdict;

		dictByPKey.remove( pkey );

		dictByULoginIdx.remove( keyULoginIdx );

		subdict = dictByEMConfIdx.get( keyEMConfIdx );
		subdict.remove( pkey );

		subdict = dictByPwdResetIdx.get( keyPwdResetIdx );
		subdict.remove( pkey );

		subdict = dictByDefDevIdx.get( keyDefDevIdx );
		subdict.remove( pkey );

	}
	public void deleteSecUserByIdIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId )
	{
		CFSecSecUserPKey key = schema.getFactorySecUser().newPKey();
		key.setRequiredSecUserId( argSecUserId );
		deleteSecUserByIdIdx( Authorization, key );
	}

	public void deleteSecUserByIdIdx( CFSecAuthorization Authorization,
		CFSecSecUserPKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecSecUserBuff cur;
		LinkedList<CFSecSecUserBuff> matchSet = new LinkedList<CFSecSecUserBuff>();
		Iterator<CFSecSecUserBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecUserBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecUser().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() );
			deleteSecUser( Authorization, cur );
		}
	}

	public void deleteSecUserByULoginIdx( CFSecAuthorization Authorization,
		String argLoginId )
	{
		CFSecSecUserByULoginIdxKey key = schema.getFactorySecUser().newULoginIdxKey();
		key.setRequiredLoginId( argLoginId );
		deleteSecUserByULoginIdx( Authorization, key );
	}

	public void deleteSecUserByULoginIdx( CFSecAuthorization Authorization,
		CFSecSecUserByULoginIdxKey argKey )
	{
		CFSecSecUserBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecUserBuff> matchSet = new LinkedList<CFSecSecUserBuff>();
		Iterator<CFSecSecUserBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecUserBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecUser().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() );
			deleteSecUser( Authorization, cur );
		}
	}

	public void deleteSecUserByEMConfIdx( CFSecAuthorization Authorization,
		CFLibUuid6 argEMailConfirmUuid6 )
	{
		CFSecSecUserByEMConfIdxKey key = schema.getFactorySecUser().newEMConfIdxKey();
		key.setOptionalEMailConfirmUuid6( argEMailConfirmUuid6 );
		deleteSecUserByEMConfIdx( Authorization, key );
	}

	public void deleteSecUserByEMConfIdx( CFSecAuthorization Authorization,
		CFSecSecUserByEMConfIdxKey argKey )
	{
		CFSecSecUserBuff cur;
		boolean anyNotNull = false;
		if( argKey.getOptionalEMailConfirmUuid6() != null ) {
			anyNotNull = true;
		}
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecUserBuff> matchSet = new LinkedList<CFSecSecUserBuff>();
		Iterator<CFSecSecUserBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecUserBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecUser().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() );
			deleteSecUser( Authorization, cur );
		}
	}

	public void deleteSecUserByPwdResetIdx( CFSecAuthorization Authorization,
		CFLibUuid6 argPasswordResetUuid6 )
	{
		CFSecSecUserByPwdResetIdxKey key = schema.getFactorySecUser().newPwdResetIdxKey();
		key.setOptionalPasswordResetUuid6( argPasswordResetUuid6 );
		deleteSecUserByPwdResetIdx( Authorization, key );
	}

	public void deleteSecUserByPwdResetIdx( CFSecAuthorization Authorization,
		CFSecSecUserByPwdResetIdxKey argKey )
	{
		CFSecSecUserBuff cur;
		boolean anyNotNull = false;
		if( argKey.getOptionalPasswordResetUuid6() != null ) {
			anyNotNull = true;
		}
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecUserBuff> matchSet = new LinkedList<CFSecSecUserBuff>();
		Iterator<CFSecSecUserBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecUserBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecUser().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() );
			deleteSecUser( Authorization, cur );
		}
	}

	public void deleteSecUserByDefDevIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 argDfltDevUserId,
		String argDfltDevName )
	{
		CFSecSecUserByDefDevIdxKey key = schema.getFactorySecUser().newDefDevIdxKey();
		key.setOptionalDfltDevUserId( argDfltDevUserId );
		key.setOptionalDfltDevName( argDfltDevName );
		deleteSecUserByDefDevIdx( Authorization, key );
	}

	public void deleteSecUserByDefDevIdx( CFSecAuthorization Authorization,
		CFSecSecUserByDefDevIdxKey argKey )
	{
		CFSecSecUserBuff cur;
		boolean anyNotNull = false;
		if( argKey.getOptionalDfltDevUserId() != null ) {
			anyNotNull = true;
		}
		if( argKey.getOptionalDfltDevName() != null ) {
			anyNotNull = true;
		}
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecUserBuff> matchSet = new LinkedList<CFSecSecUserBuff>();
		Iterator<CFSecSecUserBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecUserBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecUser().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() );
			deleteSecUser( Authorization, cur );
		}
	}
}
